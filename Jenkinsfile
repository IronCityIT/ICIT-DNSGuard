// DNS Guard quality gates.
//
// Every stage shells out to tools/gates.sh, which is the same script a developer
// runs locally. That is deliberate: a gate that only exists inside a Jenkins
// stage cannot be reproduced on a workstation, so it gets worked around rather
// than fixed.
//
// Gates are grouped so a red build names what broke. Static checks run in
// parallel because they are independent and fast; tests run alone because they
// are the slow stage and interleaving their output makes a failure harder to
// read.
//
// Nothing here deploys. Deployment for this product runs from GitHub Actions
// against its own GCP project, and giving a CI server a second path to
// production is how two systems end up disagreeing about what is live.

pipeline {
    agent any

    options {
        timestamps()
        ansiColor('xterm')
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '30', artifactNumToKeepStr: '10'))
        disableConcurrentBuilds()
    }

    environment {
        // Gate output lands here; the whole directory is archived, so a failed
        // build can be diagnosed without re-running it.
        GATE_REPORTS = "${WORKSPACE}/gate-reports"
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
        PYTHONDONTWRITEBYTECODE = '1'
        // The control plane refuses to start unauthenticated. The API tests
        // build their app explicitly, but anything that constructs a default app
        // needs a value present — a build-scoped dummy, never a real secret.
        DNSGUARD_API_TOKEN = 'ci-build-token-not-a-real-secret'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh 'git --no-pager log -1 --pretty="%h %s"'
            }
        }

        stage('Environment') {
            steps {
                sh '''
                    set -eu
                    python3 -m venv .venv
                    . .venv/bin/activate
                    python -m pip install --quiet --upgrade pip
                    # requirements-dev pulls in requirements, so the runtime deps
                    # are installed from the same manifest the product ships with.
                    python -m pip install --quiet -r requirements-dev.txt
                    python --version
                    python -m pip --version
                '''
            }
        }

        stage('Static analysis') {
            parallel {
                stage('Lint')      { steps { sh '. .venv/bin/activate && sh tools/gates.sh lint' } }
                stage('Format')    { steps { sh '. .venv/bin/activate && sh tools/gates.sh format' } }
                stage('Typecheck') { steps { sh '. .venv/bin/activate && sh tools/gates.sh typecheck' } }
            }
        }

        stage('Test') {
            steps {
                sh '. .venv/bin/activate && sh tools/gates.sh test'
            }
            post {
                always {
                    // Publish results even when the stage fails — the failing
                    // test names are the point of the report.
                    junit allowEmptyResults: false, testResults: 'gate-reports/junit.xml'
                }
            }
        }

        stage('Contracts') {
            parallel {
                stage('JSON')      { steps { sh '. .venv/bin/activate && sh tools/gates.sh json' } }
                stage('Workflows') { steps { sh '. .venv/bin/activate && sh tools/gates.sh yaml' } }
                stage('Functions') { steps { sh 'sh tools/gates.sh node' } }
                stage('Dashboard') { steps { sh 'sh tools/gates.sh dashboard' } }
            }
        }

        stage('Security') {
            steps {
                sh '. .venv/bin/activate && sh tools/gates.sh secrets'
            }
        }

        stage('Gate script') {
            steps {
                sh 'sh tools/gates.sh shell'
            }
        }

        stage('Build') {
            steps {
                sh '. .venv/bin/activate && sh tools/gates.sh build'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'gate-reports/**', allowEmptyArchive: true, fingerprint: true
            sh 'rm -rf .venv'
        }
        success {
            echo 'All gates green. This build has not deployed anything — deployment runs from GitHub Actions.'
        }
        failure {
            echo 'A gate failed. The stage name above identifies which; gate-reports/ is archived on this build.'
        }
        unstable {
            echo 'Tests reported failures. See the test result trend on this build.'
        }
    }
}
