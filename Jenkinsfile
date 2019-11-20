@Library("release-pipeline") _

def appName = 'cfssl-intelity'
def allServices = [appName]
def defaultBranch = 'master'

IS_DEFAULT_BRANCH = env.BRANCH_NAME == defaultBranch

pipeline {
    agent any

    parameters {
        booleanParam(
                name: 'DEPLOY_TO_DEV',
                description: 'Check to deploy working branch to dev',
                defaultValue: IS_DEFAULT_BRANCH,
        )
        booleanParam(
                name: 'PUBLISH_IMAGE',
                description: 'Check to publish docker images',
                defaultValue: IS_DEFAULT_BRANCH,
        )
    }

    options {
        disableConcurrentBuilds()
        timeout(time: 15, unit: 'MINUTES')
        ansiColor('xterm')
        timestamps()
    }

    stages {
        stage('Checkout') {
            steps {
                ansiColor('xterm') {
                    println '\033[1;4;37;42mStage "Checkout"\033[0m'
                }
                gitCheckout()
            }
        }

        stage('Build images') {
            steps {
                ansiColor('xterm') {
                    println '\033[1;4;37;42mStage "Build docker image"\033[0m'
                }
                script {
                    commitId = gitCommitId()
                    appEnv = dockerBuild(appName, commitId, ['dockerFile': "Dockerfile.minimal"])
                    dockerTag(appName, commitId, allServices)
                }
            }
        }

        stage('Publish & Deploy') {
            steps {
                ansiColor('xterm') {
                    println '\033[1;4;37;42mStage "Publish and deploy chart"\033[0m'
                }
                k8sDeploy(appName, [
                        forceDevDeployment: params.DEPLOY_TO_DEV,
                        forcePublish      : params.PUBLISH_IMAGE,
                        deployments       : allServices
                ])
            }
        }
    }

    post {
        always {
            deleteDir()
        }
    }
}