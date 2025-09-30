pipeline {
    agent any

    environment {
        TRIVY_SEVERITY = "HIGH,MEDIUM,LOW"
    }

    stages {
        stage('Checkout SCM') {
            steps {
                checkout scm
            }
        }

        stage('Scan Multiple Dockerfiles') {
            steps {
                script {
                    def dockerfiles = [
                        ['file': 'Dockerfile/clean/Dockerfile', 'image': 'my-nginx-clean'],
                        ['file': 'Dockerfile/misconfig/Dockerfile', 'image': 'my-nginx-misconfig'],
                        ['file': 'Dockerfile/vuln/Dockerfile', 'image': 'my-nginx-vuln']
                    ]

                    dockerfiles.each { df ->
                        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                            echo "🔨 Building and scanning ${df.file}..."

                            // Build Docker image
                            sh "docker build -f ${df.file} -t ${df.image}:latest ."

                            // Trivy image scan
                            sh "trivy image --severity ${TRIVY_SEVERITY} --format json -o ${df.image}_image.json ${df.image}:latest || true"

                            // Trivy Dockerfile scan
                            def dockerfileDir = sh(script: "dirname ${df.file}", returnStdout: true).trim()
                            sh "trivy config --severity ${TRIVY_SEVERITY} --format json -o ${df.image}_dockerfile.json ${dockerfileDir} || true"

                            // Convert JSON to CSV
                            sh "jq -r '.Results[].Vulnerabilities[]? | [.VulnerabilityID,.PkgName,.InstalledVersion,.FixedVersion,.Severity,.Title] | @csv' ${df.image}_image.json > ${df.image}_image.csv || true"
                            sh "jq -r '.Results[].Misconfigurations[]? | [.ID,.Type,.Message,.Severity,.Resolution,(.References//[] | join(\"; \"))] | @csv' ${df.image}_dockerfile.json > ${df.image}_dockerfile.csv || true"

                            // Count issues
                            def totalVulns = sh(script: "jq '[.Results[].Vulnerabilities[]?] | length' ${df.image}_image.json", returnStdout: true).trim().toInteger()
                            def highCriticalVulns = sh(script: "jq '[.Results[].Vulnerabilities[]? | select(.Severity==\"CRITICAL\" or .Severity==\"HIGH\")] | length' ${df.image}_image.json", returnStdout: true).trim().toInteger()
                            def totalMisconfigs = sh(script: "jq '[.Results[].Misconfigurations[]?] | length' ${df.image}_dockerfile.json", returnStdout: true).trim().toInteger()
                            def highCriticalMisconfigs = sh(script: "jq '[.Results[].Misconfigurations[]? | select(.Severity==\"CRITICAL\" or .Severity==\"HIGH\")] | length' ${df.image}_dockerfile.json", returnStdout: true).trim().toInteger()

                            // Calculate percentage
                            def totalIssues = totalVulns + totalMisconfigs
                            def totalHighCritical = highCriticalVulns + highCriticalMisconfigs
                            def percentage = totalIssues > 0 ? (totalHighCritical / totalIssues) * 100 : 0

                            if (percentage >= 80) {
                                error "❌ ${df.image} failed security check (>= 80% critical/high issues)! Percentage: ${percentage}%"
                            } else {
                                echo "✅ ${df.image} passed security check (< 80% critical/high issues). Percentage: ${percentage}%"
                            }
                        }
                    }
                }
            }
        }

        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: '*.json, *.csv', allowEmptyArchive: true
            }
        }
    }

    post {
        always {
            echo "🧹 Cleaning up temporary files..."
            sh 'rm -f *.json *.csv'
        }
    }
}

