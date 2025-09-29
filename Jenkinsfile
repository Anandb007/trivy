pipeline {
    agent any

    environment {
        IMAGE_NAME = "my-nginx"
        REPORT_FILE = "trivy_report.csv"
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
                    trivy config --severity HIGH,MEDIUM,LOW . > dockerfile_scan.txt
                    """
                }
            }
        }

        stage('Trivy Scan Image') {
            steps {
                script {
                    sh """
                    trivy image --format template --template \
                    '@@/usr/local/share/trivy/templates/csv.tpl' \
                    -o ${REPORT_FILE} ${IMAGE_NAME}:latest
                    """
                }
            }
        }

        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: '*.txt, *.csv', fingerprint: true
            }
        }
    }

    post {
        always {
            echo "Cleaning up..."
            sh "docker rmi ${IMAGE_NAME}:latest || true"
        }
    }
}

