pipeline {
    agent {
        node {label 'python'}
    }
    environment {
        APPLICATION_NAME = 'python-nginx'
        GIT_REPO="https://github.com/bjsheppard/python-api.git"
        GIT_BRANCH="master"
        STAGE_TAG = "promoteToQA"
        DEV_PROJECT = "dev"
        STAGE_PROJECT = "stage"
        TEMPLATE_NAME = "python-nginx"
        ARTIFACT_FOLDER = "target"
        PORT = 8081;
    }
    stages {
        stage('Get Latest Code') {
            steps {
                git branch: "${GIT_BRANCH}", url: "${GIT_REPO}"
            }
        }
        stage ("Install Dependencies") {
            steps {
                sh """
                pip install virtualenv
                virtualenv --no-site-packages .
                source bin/activate
                pip install -r app/requirements.pip
                deactivate
                """
            }
        }
        stage('Run Tests') {
            steps {
                sh '''
                source bin/activate
                nosetests app --with-xunit
                deactivate
                '''
                junit "nosetests.xml"
            }
        }
        stage ('Run Static Code Analysis') {
            steps {
                step(
                    [$class: 'CxScanBuilder', comment: '', credentialsId: '', excludeFolders: '', excludeOpenSourceFolders: '', exclusionsSetting: 'global', 
                    failBuildOnNewResults: false, failBuildOnNewSeverity: 'HIGH', 
                    filterPattern: '''!**/_cvs/**/*, !**/.svn/**/*,   !**/.hg/**/*,   !**/.git/**/*,  !**/.bzr/**/*, !**/bin/**/*,
                    !**/obj/**/*,  !**/backup/**/*, !**/.idea/**/*, !**/*.DS_Store, !**/*.ipr,     !**/*.iws,
                    !**/*.bak,     !**/*.tmp,       !**/*.aac,      !**/*.aif,      !**/*.iff,     !**/*.m3u, !**/*.mid, !**/*.mp3,
                    !**/*.mpa,     !**/*.ra,        !**/*.wav,      !**/*.wma,      !**/*.3g2,     !**/*.3gp, !**/*.asf, !**/*.asx,
                    !**/*.avi,     !**/*.flv,       !**/*.mov,      !**/*.mp4,      !**/*.mpg,     !**/*.rm,  !**/*.swf, !**/*.vob,
                    !**/*.wmv,     !**/*.bmp,       !**/*.gif,      !**/*.jpg,      !**/*.png,     !**/*.psd, !**/*.tif, !**/*.swf,
                    !**/*.jar,     !**/*.zip,       !**/*.rar,      !**/*.exe,      !**/*.dll,     !**/*.pdb, !**/*.7z,  !**/*.gz,
                    !**/*.tar.gz,  !**/*.tar,       !**/*.gz,       !**/*.ahtm,     !**/*.ahtml,   !**/*.fhtml, !**/*.hdm,
                    !**/*.hdml,    !**/*.hsql,      !**/*.ht,       !**/*.hta,      !**/*.htc,     !**/*.htd, !**/*.war, !**/*.ear,
                    !**/*.htmls,   !**/*.ihtml,     !**/*.mht,      !**/*.mhtm,     !**/*.mhtml,   !**/*.ssi, !**/*.stm,
                    !**/*.stml,    !**/*.ttml,      !**/*.txn,      !**/*.xhtm,     !**/*.xhtml,   !**/*.class, !**/*.iml, !Checkmarx/Reports/*.*''', 
                    fullScanCycle: 10, groupId: '417ae471-3b34-4a90-a221-3224848d4f59', includeOpenSourceFolders: '', osaArchiveIncludePatterns: '*.zip, *.war, *.ear, *.tgz', 
                    osaInstallBeforeScan: false, password: '{AQAAABAAAAAQ30uz9Sb2kwrCQtjkp7lPrBzZosREuO8ApiI8kkE03/4=}', preset: '36', projectName: 'FWB-test', 
                    sastEnabled: true, serverUrl: 'https://services.csa.spawar.navy.mil/', sourceEncoding: '1', username: '', vulnerabilityThresholdResult: 'FAILURE', 
                    waitForResultsEnabled: true]
                )
            }
        }
        stage("CodeDx Scan") {
            steps {
                withCredentials([string(credentialsId: 'codedx-jenkins-apikey', variable: 'ApiTokenCodeDx')]) {
                    echo "Starting CodeDX Aggregation..."
                    /*
                    use of single-quotes(''') instead of double-quotes(""") to define the script (the implicit parameter to sh) in Groovy above. The single-quotes will cause the
                    secret to be expanded by the shell as an environment variable. The double-quotes are potentially less secure as the secret is interpolated by Groovy,
                    and so typical operating system process listings (as well as Blue Ocean, and the pipeline steps tree in the classic UI) will accidentally disclose it
                    */
                    sh '''
                        #--------------------------------------------------------------------------------------------------------------------------------------------------------------
                        #---required---
                        #specify project name
                        prj="FWB"
                        #---optional---
                        nprefix="test"
                        DATE=$(date '+%Y-%m-%d_%H:%M:%S')
                        rptName=${nprefix}${prj}CodeDxReport_${DATE}
                        #pdf or xml
                        rptType="xml"
                        #asdstig or none
                        stdType="asdstig"
                        #---constant--- (do not modify)
                        codeDxServer="https://services.csa.spawar.navy.mil"
                        #--------------------------------------------------------------------------------------------------------------------------------------------------------------
                        #retrieve project id (get first match-should be unique)
                        postDataJson='{\"filter\":{\"name\":\"'${prj}'\"}}'
                        prjIdn=$(curl -k -H "Content-Type:application/json" -H "API-Key:$ApiTokenCodeDx" -X POST "${codeDxServer}/codedx/api/projects/query" --data "${postDataJson}" | python -c "import sys, json; print json.load(sys.stdin)[0]['id']")
                        #get project's tool-connector id(s) (TODO:iterate over all connectors if multiple)
                        contorIdn=$(curl -k -H "API-Key:$ApiTokenCodeDx" -X GET "${codeDxServer}/codedx/x/tool-connector-config/entries/${prjIdn}" | python -c "import sys, json; print json.load(sys.stdin)[0]['id']")
                        #trigger analysis
                        jobIdn=$(curl -k -H "API-Key:$ApiTokenCodeDx" -X POST "${codeDxServer}/codedx/x/tool-connector-config/entries/${prjIdn}/${contorIdn}/analysis" | python -c "import sys, json; print json.load(sys.stdin)['jobId']")
                        #wait for analysis to complete - Query Job Status endpoint until it responds with completed
                        jobSts="queued"
                        until [  $jobSts == "completed" ];
                        do
                                        jobSts=$(curl -k -H "API-Key:$ApiTokenCodeDx" -X GET "${codeDxServer}/codedx/api/jobs/${jobIdn}" | python -c "import sys, json; print json.load(sys.stdin)['status']" )
                                        #delay
                                        sleep 20s
                        done
                        #~~~~generate report~~~~#
                        #chose filter "asdstig" or "none"
                        if [ "$stdType" = "asdstig" ]; then
                                #Use "countBy" field of standard name: "DISA STIG 4.3" to return standards filter field value - this may change on a per project basis hency why not hardcoded
                                postDataJson='{\"filter\":{},\"countBy\":\"standard:27\"}'
                                stdIdn=$(curl -k -H "API-Key:$ApiTokenCodeDx" -H "Content-Type: application/json" -X POST "${codeDxServer}/codedx/api/projects/${prjIdn}/findings/grouped-counts" --data "${postDataJson}" | python -c "import sys, json; print json.load(sys.stdin)[0]['id']")
                                filtStr='{\"standard\":[\"'${stdIdn}'\"],\"~status\":\"gone\"}'
                                #update rptname to reflect filter
                                rptName=${rptName=}'_ASDSTIGv4.3'
                        else
                                filtStr='{\"~status\":\"gone\"}'
                        fi
                        #chose report format "pdf" or "xml"
                        if [ "$rptType" = "pdf" ]; then
                                postDataJson='{\"filter\":'${filtStr}',\"config\":{\"summaryMode\":\"simple\",\"detailsMode\":\"with-source\",\"includeResultDetails\":true,\"includeComments\":false,\"includeRequestResponse\":false}}'
                                #postDataJson='{\"filter\":{},\"config\":{\"summaryMode\":\"simple\",\"detailsMode\":\"with-source\",\"includeResultDetails\":true,\"includeComments\":false,\"includeRequestResponse\":false}}'
                        else
                                postDataJson='{\"filter\":'${filtStr}',\"config\":{\"includeStandards\":true,\"includeSource\":true,\"includeRuleDescriptions\":true}}'
                                #postDataJson='{\"filter\":{},\"config\":{\"includeStandards\":true,\"includeSource\":true,\"includeRuleDescriptions\":true}}'
                        fi
                        jobIdn=$(curl -k -H "Content-Type: application/json" -H "API-Key:$ApiTokenCodeDx" -X POST "${codeDxServer}/codedx/api/projects/${prjIdn}/report/${rptType}" --data "${postDataJson}" | python -c "import sys, json; print json.load(sys.stdin)['jobId']")
                        jobSts="queued"
                        #wait for report to generate - Query Job Status endpoint until it responds with completed
                        until [  $jobSts == "completed" ];
                        do
                                        jobSts=$(curl -k -H "API-Key:$ApiTokenCodeDx" -X GET "${codeDxServer}/codedx/api/jobs/${jobIdn}" | python -c "import sys, json; print json.load(sys.stdin)['status']" )
                                        #delay
                                        sleep 20s
                        done
                        #download report - Once the Job is complete, use the Get Job Result endpoint to download the report
                        curl -k -H "Content-Type:application/${rptType}" -H "API-Key:$ApiTokenCodeDx" -X GET "${codeDxServer}/codedx/api/jobs/${jobIdn}/result" --output "${rptName}.${rptType}"
                    '''
                }
            }
        }
        stage('Store Artifact'){
            steps{
                script{
                    def safeBuildName  = "${APPLICATION_NAME}_${BUILD_NUMBER}",
                        artifactFolder = "${ARTIFACT_FOLDER}",
                        fullFileName   = "${safeBuildName}.tar.gz",
                        applicationZip = "${artifactFolder}/${fullFileName}"
                        applicationDir = ["app",
                                          "config",
                                          "Dockerfile",
                                         ].join(" ");
                    def needTargetPath = !fileExists("${artifactFolder}")
                    if (needTargetPath) {
                        sh "mkdir ${artifactFolder}"
                    }
                    sh "tar -czvf ${applicationZip} ${applicationDir}"
                    archiveArtifacts artifacts: "${applicationZip}", excludes: null, onlyIfSuccessful: true
                }
            }
        }
        stage('Create Image Builder') {
            when {
                expression {
                    openshift.withCluster() {
                        openshift.withProject(DEV_PROJECT) {
                            return !openshift.selector("bc", "${TEMPLATE_NAME}").exists();
                        }
                }
            }
        }
        steps {
            script {
                openshift.withCluster() {
                    openshift.withProject(DEV_PROJECT) {
                        openshift.newBuild("--name=${TEMPLATE_NAME}", "--docker-image=docker.io/nginx:mainline-alpine", "--binary=true")
                        }
                    }
                }
            }
        }
        stage('Build Image') {
            steps {
                script {
                    openshift.withCluster() {
                        openshift.withProject(env.DEV_PROJECT) {
                            openshift.selector("bc", "$TEMPLATE_NAME").startBuild("--from-archive=${ARTIFACT_FOLDER}/${APPLICATION_NAME}_${BUILD_NUMBER}.tar.gz", "--wait=true")
                        }
                    }
                }
            }
        }
        stage('Deploy to DEV') {
            when {
                expression {
                    openshift.withCluster() {
                        openshift.withProject(env.DEV_PROJECT) {
                            return !openshift.selector('dc', "${TEMPLATE_NAME}").exists()
                        }
                    }
                }
            }
            steps {
                script {
                    openshift.withCluster() {
                        openshift.withProject(env.DEV_PROJECT) {
                            def app = openshift.newApp("${TEMPLATE_NAME}:latest")
                            app.narrow("svc").expose("--port=${PORT}");
                            def dc = openshift.selector("dc", "${TEMPLATE_NAME}")
                            while (dc.object().spec.replicas != dc.object().status.availableReplicas) {
                                sleep 10
                            }
                        }
                    }
                }
            }
        }
        stage('Promote to STAGE?') {
            steps {
                timeout(time:15, unit:'MINUTES') {
                    input message: "Promote to STAGE?", ok: "Promote"
                }
                script {
                    openshift.withCluster() {
                        openshift.tag("${DEV_PROJECT}/${TEMPLATE_NAME}:latest", "${STAGE_PROJECT}/${TEMPLATE_NAME}:${STAGE_TAG}")
                    }
                }
            }
        }
        stage('Rollout to STAGE') {
            steps {
                script {
                    openshift.withCluster() {
                        openshift.withProject(STAGE_PROJECT) {
                            if (openshift.selector('dc', '${TEMPLATE_NAME}').exists()) {
                                openshift.selector('dc', '${TEMPLATE_NAME}').delete()
                                openshift.selector('svc', '${TEMPLATE_NAME}').delete()
                                openshift.selector('route', '${TEMPLATE_NAME}').delete()
                            }
                        openshift.newApp("${TEMPLATE_NAME}:${STAGE_TAG}").narrow("svc").expose("--port=${PORT}")
                        }
                    }
                } 
            }
        }
        // stage('Scale in STAGE') {
        //     steps {
        //         script {
        //             openshiftScale(namespace: "${STAGE_PROJECT}", deploymentConfig: "${TEMPLATE_NAME}", replicaCount: '3')
        //         }
        //     }
        // }
    }
}