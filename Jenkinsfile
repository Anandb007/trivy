pipeline {
    agent any

    environment {
        IMAGE_NAME = "my-nginx"
        DOCKERFILE_JSON = "dockerfile_scan.json"
        DOCKERFILE_CSV = "dockerfile_scan.csv"
        IMAGE_JSON = "trivy_report.json"
        IMAGE_CSV = "trivy_report.csv"
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
                    # Scan Dockerfile in JSON
                    trivy config --severity HIGH,MEDIUM,LOW --format json -o ${DOCKERFILE_JSON} .

                    # Convert JSON → CSV using jq
                    jq -r '
                      .Results[].Misconfigurations[] | [
                        .ID,
                        .Type,
                        .Message,
                        .Severity,
                        .Resolution,
                        (.References // [] | join("; "))
                      ] | @csv' ${DOCKERFILE_JSON} > ${DOCKERFILE_CSV}
                    """
                }
            }
        }

        stage('Trivy Scan Docker Image') {
            steps {
                script {
                    sh """
                    # Scan Docker image in JSON
                    trivy image --format json -o ${IMAGE_JSON} ${IMAGE_NAME}:latest

                    # Convert JSON → CSV using jq
                    jq -r '
                      .Results[].Vulnerabilities[] | [
                        .VulnerabilityID,
                        .PkgName,
                        .InstalledVersion,
                        .FixedVersion,
                        .Severity,
                        .Title
                      ] | @csv' ${IMAGE_JSON} > ${IMAGE_CSV}
                    """
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
            echo "Cleaning up Docker image..."
            sh "docker rmi ${IMAGE_NAME}:latest || true"
        }
    }
}

