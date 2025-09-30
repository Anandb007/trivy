pipeline {
    agent any

    environment {
        VULN_THRESHOLD = 80
        TRIVY_SEVERITY = "HIGH,MEDIUM,LOW"
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: 'master', url: 'https://github.com/Anandb007/trivy.git'
            }
        }

        stage('Build & Scan Dockerfiles') {
            steps {
                script {
                    // List of Dockerfiles and corresponding image names
                    def dockerfiles = [
                        ['path': 'Dockerfile/clean/Dockerfile',     'image': 'my-nginx-clean'],
                        ['path': 'Dockerfile/misconfig/Dockerfile', 'image': 'my-nginx-misconfig'],
                        ['path': 'Dockerfile/vuln/Dockerfile',      'image': 'my-nginx-vuln']
                    ]

                    dockerfiles.each { df ->
                        echo "🔨 Building Docker image for ${df.path}"
                        sh "docker build -f ${df.path} -t ${df.image}:latest ."

                        echo "🔍 Scanning image ${df.image}..."
                        sh """
                        trivy image --severity ${TRIVY_SEVERITY} --format json -o ${df.image}_image.json ${df.image}:latest
                        jq -r '.Results[].Vulnerabilities[]? | [.VulnerabilityID,.PkgName,.InstalledVersion,.FixedVersion,.Severity,.Title] | @csv' ${df.image}_image.json > ${df.image}_image.csv || true
                        """

                        echo "📂 Scanning Dockerfile for misconfigurations..."
                        sh """
                        trivy config --severity ${TRIVY_SEVERITY} --format json -o ${df.image}_dockerfile.json \$(dirname ${df.path})
                        jq -r '.Results[].Misconfigurations[]? | [.ID,.Type,.Message,.Severity,.Resolution,(.References//[] | join("; "))] | @csv' ${df.image}_dockerfile.json > ${df.image}_dockerfile.csv || true
                        """

                        echo "📊 Calculating vulnerability count..."
                        def vulnCount = sh(
                            script: "jq '[.Results[].Vulnerabilities[]?] | length' ${df.image}_image.json",
                            returnStdout: true
                        ).trim().toInteger()

                        def misconfigCount = sh(
                            script: "jq '[.Results[].Misconfigurations[]?] | length' ${df.image}_dockerfile.json",
                            returnStdout: true
                        ).trim().toInteger()

                        def totalIssues = vulnCount + misconfigCount
                        echo "Total issues found for ${df.image}: ${totalIssues}"

                        if (totalIssues > VULN_THRESHOLD.toInteger()) {
                            error "❌ Build failed! ${df.image} exceeded vulnerability threshold (${totalIssues} > ${VULN_THRESHOLD})"
                        } else {
                            echo "✅ ${df.image} passed security scan (Issues: ${totalIssues})"
                        }

                        echo "🧹 Cleaning up Docker image ${df.image}"
                        sh "docker rmi ${df.image}:latest || true"
                    }
                }
            }
        }

        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: '*.json, *.csv', fingerprint: true
            }
        }
    }

    post {
        always {
            echo "🧹 Cleaning up leftover files..."
            sh "rm -f *.json *.csv || true"
        }
    }
}

