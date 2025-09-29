pipeline {
    agent any

    environment {
        IMAGE_NAME = "my-nginx"
        REPORT_JSON = "trivy_report.json"
        REPORT_CSV = "trivy_report.csv"
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: 'master', url: 'https://github.com/Anandb007/trivy.git'
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    sh "docker build -t ${IMAGE_NAME}:latest ."
                }
            }
        }

        stage('Trivy Scan Dockerfile') {
            steps {
                script {
                    sh """
                    # Scan Dockerfile for misconfigurations
                    trivy config --severity HIGH,MEDIUM,LOW . > dockerfile_scan.txt
                    """
                }
            }
        }

        stage('Trivy Scan Docker Image') {
            steps {
                script {
                    sh """
                    # Scan Docker image and save as JSON
                    trivy image --format json -o ${REPORT_JSON} ${IMAGE_NAME}:latest

                    # Convert JSON to CSV using jq
                    jq -r '
                        .Results[].Vulnerabilities[] | [
                          .VulnerabilityID,
                          .PkgName,
                          .InstalledVersion,
                          .FixedVersion,
                          .Severity,
                          .Title
                        ] | @csv' ${REPORT_JSON} > ${REPORT_CSV}
                    """
                }
            }
        }

        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: '*.txt, *.json, *.csv', fingerprint: true
            }
        }
    }

    post {
        always {
            echo "Cleaning up Docker image..."
            sh "docker rmi ${IMAGE_NAME}:latest || true"
        }
    }
}

