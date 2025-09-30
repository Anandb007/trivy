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
                    // List of Dockerfiles and corresponding image names
                    def dockerfiles = [
                        ['file': 'Dockerfile/clean/Dockerfile', 'image': 'my-nginx-clean'],
                        ['file': 'Dockerfile/misconfig/Dockerfile', 'image': 'my-nginx-misconfig'],
                        ['file': 'Dockerfile/vuln/Dockerfile', 'image': 'my-nginx-vuln']
                    ]

                    dockerfiles.each { df ->
                        echo "Building and scanning ${df.file}..."

                        // Build Docker image
                        sh "docker build -f ${df.file} -t ${df.image}:latest ."

                        // Scan image for vulnerabilities
                        sh "trivy image --severity ${TRIVY_SEVERITY} --format json -o ${df.image}_image.json ${df.image}:latest || true"

                        // Scan Dockerfile/config for misconfigurations
                        def dockerfileDir = sh(script: "dirname ${df.file}", returnStdout: true).trim()
                        sh "trivy config --severity ${TRIVY_SEVERITY} --format json -o ${df.image}_dockerfile.json ${dockerfileDir} || true"

                        // Convert JSON to CSV
                        sh "jq -r '.Results[].Vulnerabilities[]? | [.VulnerabilityID,.PkgName,.InstalledVersion,.FixedVersion,.Severity,.Title] | @csv' ${df.image}_image.json > ${df.image}_image.csv || true"
                        sh "jq -r '.Results[].Misconfigurations[]? | [.ID,.Type,.Message,.Severity,.Resolution,(.References//[] | join(\"; \"))] | @csv' ${df.image}_dockerfile.json > ${df.image}_dockerfile.csv || true"

                        // Count vulnerabilities
                        def totalVulns = sh(
                            script: "jq '[.Results[].Vulnerabilities[]?] | length' ${df.image}_image.json",
                            returnStdout: true
                        ).trim().toInteger()

                        def highCriticalVulns = sh(
                            script: "jq '[.Results[].Vulnerabilities[]? | select(.Severity==\"CRITICAL\" or .Severity==\"HIGH\")] | length' ${df.image}_image.json",
                            returnStdout: true
                        ).trim().toInteger()

                        def totalMisconfigs = sh(
                            script: "jq '[.Results[].Misconfigurations[]?] | length' ${df.image}_dockerfile.json",
                            returnStdout: true
                        ).trim().toInteger()

                        def highCriticalMisconfigs = sh(
                            script: "jq '[.Results[].Misconfigurations[]? | select(.Severity==\"CRITICAL\" or .Severity==\"HIGH\")] | length' ${df.image}_dockerfile.json",
                            returnStdout: true
                        ).trim().toInteger()

                        def totalIssues = totalVulns + totalMisconfigs
                        def totalHighCritical = highCriticalVulns + highCriticalMisconfigs

                        echo "Total issues for ${df.image}: ${totalIssues}, Critical/High: ${totalHighCritical}"

                        // Calculate percentage of critical/high issues
                        def percentage = totalIssues > 0 ? (totalHighCritical / totalIssues) * 100 : 0
                        echo "Percentage of critical/high issues for ${df.image}: ${percentage}%"

                        if (percentage >= 80) {
                            echo "❌ ${df.image} failed security check (>= 80% critical/high issues)!"
                        } else {
                            echo "✅ ${df.image} passed security check (< 80% critical/high issues)."
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
            echo "Cleaning up temporary files..."
            sh 'rm -f *.json *.csv'
        }
    }
}

