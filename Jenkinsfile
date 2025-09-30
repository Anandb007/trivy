pipeline {
    agent any

    environment {
        VULN_THRESHOLD = 80
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: 'master', url: 'https://github.com/Anandb007/trivy.git'
            }
        }

        stage('Scan Multiple Dockerfiles') {
            steps {
                script {
                    // Updated Dockerfile paths
                    def dockerfiles = [
                        ['path': 'Dockerfile/clean/Dockerfile', 'image': 'my-nginx-clean'],
                        ['path': 'Dockerfile/misconfig/Dockerfile', 'image': 'my-nginx-misconfig'],
                        ['path': 'Dockerfile/vuln/Dockerfile', 'image': 'my-nginx-vuln']
                    ]

                    dockerfiles.each { df ->
                        echo "Building and scanning ${df.path}..."

                        // Build Docker image
                        sh "docker build -f ${df.path} -t ${df.image}:latest ."

                        // Dockerfile config scan
                        sh """
                        trivy config --severity HIGH,MEDIUM,LOW --format json -o ${df.image}_dockerfile.json -f ${df.path}
                        jq -r '.Results[].Misconfigurations[] | [.ID,.Type,.Message,.Severity,.Resolution,(.References//[] | join("; "))] | @csv' ${df.image}_dockerfile.json > ${df.image}_dockerfile.csv
                        """

                        // Docker image scan
                        sh """
                        trivy image --severity HIGH,MEDIUM,LOW --format json -o ${df.image}_image.json ${df.image}:latest
                        jq -r '.Results[].Vulnerabilities[] | [.VulnerabilityID,.PkgName,.InstalledVersion,.FixedVersion,.Severity,.Title] | @csv' ${df.image}_image.json > ${df.image}_image.csv
                        """

                        // Calculate total vulnerabilities
                        def dockerfileVuln = sh(script: "jq '.Results[].Misconfigurations | length' ${df.image}_dockerfile.json | awk '{s+=\$1} END {print s}'", returnStdout: true).trim()
                        def imageVuln = sh(script: "jq '.Results[].Vulnerabilities | length' ${df.image}_image.json | awk '{s+=\$1} END {print s}'", returnStdout: true).trim()
                        def totalVulns = dockerfileVuln.toInteger() + imageVuln.toInteger()

                        echo "Total vulnerabilities for ${df.image}: ${totalVulns}"

                        if (totalVulns > VULN_THRESHOLD.toInteger()) {
                            error "Build failed! Vulnerabilities exceed threshold for ${df.image}."
                        } else {
                            echo "Scan passed for ${df.image}."
                        }

                        // Clean up Docker image after scan
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
            echo "Cleaning up temporary files..."
            sh "rm -f *.json *.csv"
        }
    }
}

