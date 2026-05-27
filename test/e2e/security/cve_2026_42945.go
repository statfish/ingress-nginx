/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package security

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/assert"

	"k8s.io/ingress-nginx/test/e2e/framework"
)

var _ = framework.IngressNginxDescribe("[Security] CVE-2026-42945 nginx rift", func() {
	f := framework.NewDefaultFramework("cve-2026-42945")

	ginkgo.BeforeEach(func() {
		f.NewEchoDeployment()
	})

	ginkgo.It("should not crash worker when rewrite uses unnamed capture with question mark followed by set", func() {
		host := "cve-2026-42945.test"

		ginkgo.By("creating an ingress with the vulnerable pattern: rewrite-target /$2 with unnamed captures")
		annotations := map[string]string{
			"nginx.ingress.kubernetes.io/use-regex":              "true",
			"nginx.ingress.kubernetes.io/rewrite-target":         "/$2?migrated=true",
			"nginx.ingress.kubernetes.io/configuration-snippet":  "set $original_uri $1;",
		}
		ing := framework.NewSingleIngress(host, "/api(/|$)(.*)", host, f.Namespace, framework.EchoService, 80, annotations)
		f.EnsureIngress(ing)

		f.WaitForNginxServer(host,
			func(server string) bool {
				return strings.Contains(server, `location ~* "^/api(/|$)(.*)"`)
			})

		ginkgo.By("sending a request with characters that expand during re-escaping (+ and &)")
		payload := strings.Repeat("A", 200) + strings.Repeat("+", 500)

		f.HTTPTestClient().
			GET("/api/" + payload).
			WithHeader("Host", host).
			Expect().
			Status(http.StatusOK)

		ginkgo.By("verifying the worker did not crash by making a followup request")
		f.HTTPTestClient().
			GET("/api/healthcheck").
			WithHeader("Host", host).
			Expect().
			Status(http.StatusOK)

		ginkgo.By("checking nginx logs for signs of worker crash")
		logs, err := f.NginxLogs()
		assert.Nil(ginkgo.GinkgoT(), err, "obtaining nginx logs")
		assert.NotContains(ginkgo.GinkgoT(), logs, "signal 11 (SIGSEGV)")
		assert.NotContains(ginkgo.GinkgoT(), logs, "signal 6 (SIGABRT)")
		assert.NotContains(ginkgo.GinkgoT(), logs, "worker process")
		assert.NotContains(ginkgo.GinkgoT(), logs, "exited on signal")
	})

	ginkgo.It("should handle rewrite with unnamed capture and question mark without buffer overrun", func() {
		host := "cve-2026-42945-basic.test"

		ginkgo.By("creating an ingress that mirrors the PoC trigger pattern")
		annotations := map[string]string{
			"nginx.ingress.kubernetes.io/use-regex":              "true",
			"nginx.ingress.kubernetes.io/rewrite-target":         "/internal?c=1",
			"nginx.ingress.kubernetes.io/configuration-snippet":  "set $ep $1;",
		}
		ing := framework.NewSingleIngress(host, "/vuln/(.*)", host, f.Namespace, framework.EchoService, 80, annotations)
		f.EnsureIngress(ing)

		f.WaitForNginxServer(host,
			func(server string) bool {
				return strings.Contains(server, `location ~* "^/vuln/(.*)"`)
			})

		ginkgo.By("sending multiple requests to exercise the rewrite path")
		for i := 0; i < 10; i++ {
			f.HTTPTestClient().
				GET(fmt.Sprintf("/vuln/endpoint%d", i)).
				WithHeader("Host", host).
				Expect().
				Status(http.StatusOK)
		}

		ginkgo.By("confirming nginx is still healthy after all requests")
		logs, err := f.NginxLogs()
		assert.Nil(ginkgo.GinkgoT(), err, "obtaining nginx logs")
		assert.NotContains(ginkgo.GinkgoT(), logs, "SIGSEGV")
		assert.NotContains(ginkgo.GinkgoT(), logs, "SIGABRT")
	})
})
