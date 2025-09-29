pipeline {
    agent any

    environment {
        IMAGE_NAME = "my-nginx"
        REPORT_FILE = "trivy_report.csv"
        SORTED_REPORT_FILE = "trivy_report_sorted.csv"
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
                    # Scan Docker image and save as CSV
                    trivy image --format csv -o ${REPORT_FILE} ${IMAGE_NAME}:latest

                    # Optional: Sort CSV by severity (CRITICAL -> HIGH -> MEDIUM -> LOW)
                    awk -F',' 'NR==1{header=\$0; next} 
                        \$7=="CRITICAL"{crit=crit \$0 "\\n"} 
                        \$7=="HIGH"{high=high \$0 "\\n"} 
                        \$7=="MEDIUM"{med=med \$0 "\\n"} 
                        \$7=="LOW"{low=low \$0 "\\n"} 
                        END{print header; printf crit high med low}' ${REPORT_FILE} > ${SORTED_REPORT_FILE}
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
            echo "Cleaning up Docker image..."
            sh "docker rmi ${IMAGE_NAME}:latest || true"
        }
    }
}

