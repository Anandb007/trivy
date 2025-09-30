pipeline {
    agent any

    environment {
        TRIVY_SEVERITY = "HIGH,MEDIUM,LOW"
    }

    stages {
        stage('Build & Scan Multiple Dockerfiles') {
            steps {
                script {
                    // List of Dockerfiles and corresponding image names
                    def dockerfiles = [
                        ['path': 'Dockerfile/clean/Dockerfile', 'image': 'my-nginx-clean'],
                        ['path': 'Dockerfile/misconfig/Dockerfile', 'image': 'my-nginx-misconfig'],
                        ['path': 'Dockerfile/vuln/Dockerfile', 'image': 'my-nginx-vuln']
                    ]

                    dockerfiles.each { df ->
                        echo "Building and scanning ${df.path}"

                        // Build Docker image
                        sh "docker build -f ${df.path} -t ${df.image}:latest ."

                        // Scan Docker image with Trivy
                        sh """
                        trivy image --severity ${TRIVY_SEVERITY} --format json -o ${df.image}_image.json ${df.image}:latest
                        jq -r '.Results[].Vulnerabilities[] | [.VulnerabilityID,.PkgName,.InstalledVersion,.FixedVersion,.Severity,.Title] | @csv' ${df.image}_image.json > ${df.image}_image.csv
                        """

                        // Scan Dockerfile (config scan)
                        sh """
                        trivy config --severity ${TRIVY_SEVERITY} --format json -o ${df.image}_dockerfile.json \$(dirname ${df.path})
                        jq -r '.Results[].Misconfigurations[] | [.ID,.Type,.Message,.Severity,.Resolution,(.References//[] | join("; "))] | @csv' ${df.image}_dockerfile.json > ${df.image}_dockerfile.csv
                        """
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
            echo 'Cleaning up temporary files...'
            sh 'rm -f *.json *.csv'
        }
    }
}

