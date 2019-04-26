@Library("release-pipeline") _

def defaultBranch = "master"
def currentBranch = env.BRANCH_NAME == null? defaultBranch : env.BRANCH_NAME

pipeline {
    agent any

    parameters {
        booleanParam(defaultValue: false, description: 'Whether to publish docker image', name: 'PUBLISH_IMAGE')
    }

    options {
        disableConcurrentBuilds()
        timeout(time: 15, unit: 'MINUTES')
        ansiColor('xterm')
        timestamps()
    }

    stages {
        stage('Build') {
            steps {
                script {
                    def commitId = gitCommitId()
                    docker.build("cfssl-intelity:${commitId}", "-f Dockerfile.minimal .")
                }
            }
        }

        stage('Publish') {
            when { expression { params.PUBLISH_IMAGE } }
            steps {
                script {
                    def commitId = gitCommitId()
                    publishDockerImage('cfssl-intelity', commitId, 'latest')
                }
            }
        }

    }
}