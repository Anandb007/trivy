pipeline {
    agent any

    environment {
        REGISTRY = "my-docker-registry"   // change if pushing images
    }

    stages {
        stage('Build & Scan Docker Images') {
            steps {
                script {
                    // Define Dockerfiles and their image tags
                    def dockerfiles = [
                        [path: 'Dockerfile/clean/Dockerfile.clean', image: 'my-nginx-clean'],
                        [path: 'Dockerfile/misconfig/Dockerfile.misconfig', image: 'my-nginx-misconfig'],
                        [path: 'Dockerfile/vuln/Dockerfile.vuln', image: 'my-nginx-vuln']
                    ]

                    def results = [:] // Store scan results

                    dockerfiles.each { df ->
                        echo "Building image for ${df.image}..."
                        sh """
                            docker build -f ${df.path} -t ${df.image}:latest .
                        """

                        echo "Scanning image ${df.image} with Trivy..."
                        sh """
                            trivy image --format json --output trivy-${df.image}.json ${df.image}:latest || true
                            trivy image --format csv  --output trivy-${df.image}.csv  ${df.image}:latest || true
                        """

                        // Evaluate scan results (JSON parsing)
                        def vulnSummary = sh(
                            script: "jq -r '[.Results[].Vulnerabilities[]?.Severity] | group_by(.) | map({(.[0]): length}) | add' trivy-${df.image}.json",
                            returnStdout: true
                        ).trim()

                        echo "Vulnerability summary for ${df.image}: ${vulnSummary}"

                        def total = sh(script: "jq '[.Results[].Vulnerabilities[]?] | length' trivy-${df.image}.json", returnStdout: true).trim().toInteger()
                        def critical = sh(script: "jq '[.Results[].Vulnerabilities[]? | select(.Severity==\"CRITICAL\")] | length' trivy-${df.image}.json", returnStdout: true).trim().toInteger()

                        // Calculate "pass percentage" → 100 - (critical/total)*100
                        def passPercent = (total > 0) ? (100 - (critical * 100 / total)) : 100
                        echo "Pass percentage for ${df.image}: ${passPercent}%"

                        // Fail only if CRITICAL or pass < 80%
                        if (critical > 0 || passPercent < 80) {
                            echo "❌ ${df.image} failed due to critical vulns or <80% threshold"
                            results[df.image] = "FAIL"
                        } else {
                            echo "✅ ${df.image} passed scan"
                            results[df.image] = "PASS"
                        }
                    }

                    // Summary of all scans
                    echo "Scan results: ${results}"
                }
            }
        }

        stage('Publish Trivy Reports') {
            steps {
                recordIssues(
                    tools: [csv(pattern: 'trivy-*.csv')],
                    trendChartType: 'TOOLS_ONLY'
                )
            }
        }

        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: 'trivy-*.json, trivy-*.csv', allowEmptyArchive: true
            }
        }
    }

    post {
        always {
            echo "Cleaning up temporary files..."
            sh 'rm -f trivy-*.json trivy-*.csv || true'
        }
    }
}

