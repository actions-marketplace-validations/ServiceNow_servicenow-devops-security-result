const core = require('@actions/core');
const axios = require('axios');

(async function main() {
    let instanceUrl = core.getInput('instance-url', { required: true });
    const securityToolId = core.getInput('security-tool-id', { required: true });
    const toolId = core.getInput('tool-id', { required: true });
    const username = core.getInput('devops-integration-user-name', { required: true });
    const password = core.getInput('devops-integration-user-password', { required: true });
    const jobname = core.getInput('job-name', { required: true });
    let securityResultAttributes = core.getInput('security-result-attributes', { required: true });

    let githubContext = core.getInput('context-github', { required: true });

    try {
        githubContext = JSON.parse(githubContext);
    } catch (e) {
        core.setFailed(`Exception parsing github context ${e}`);
    }

    try {
        securityResultAttributes = JSON.parse(securityResultAttributes);
    } catch (e) {
        core.setFailed(`Exception parsing securityResultAttributes ${e}`);
    }

    let payload;

    try {
        instanceUrl = instanceUrl.trim();
        if (instanceUrl.endsWith('/'))
            instanceUrl = instanceUrl.slice(0, -1);

        pipelineInfo = {
            toolId: toolId,
            runId: `${githubContext.run_id}`,
            runNumber: `${githubContext.run_number}`,
            runAttempt: `${githubContext.run_attempt}`,
            job: `${jobname}`,
            sha: `${githubContext.sha}`,
            workflow: `${githubContext.workflow}`,
            repository: `${githubContext.repository}`,
            ref: `${githubContext.ref}`,
            refName: `${githubContext.ref_name}`,
            refType: `${githubContext.ref_type}`
        };

        payload = {
            pipelineInfo: pipelineInfo,
            securityToolId: securityToolId,
            securityResultAttributes: securityResultAttributes
        };

        core.debug('Security scan results Custon Action payload is : ${JSON.stringify(pipelineInfo)}\n\n');
    } catch (e) {
        core.setFailed(`Exception setting the payload ${e}`);
        return;
    }

    let result;
    const endpoint = `${instanceUrl}/api/sn_devops/devops/tool/security?toolId=${toolId}`;

    try {
        const token = `${username}:${password}`;
        const encodedToken = Buffer.from(token).toString('base64');

        const defaultHeaders = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Basic ' + `${encodedToken}`
        };

        let httpHeaders = { headers: defaultHeaders };
        result = await axios.post(endpoint, JSON.stringify(payload), httpHeaders);
    } catch (e) {
        if (e.message.includes('ECONNREFUSED') || e.message.includes('ENOTFOUND') || e.message.includes('405')) {
            core.setFailed('ServiceNow Instance URL is NOT valid. Please correct the URL and try again.');
        } else if (e.message.includes('401')) {
            core.setFailed('Invalid Credentials. Please correct the credentials and try again.');
        } else {
            core.setFailed(`ServiceNow Security Results are NOT created. Please check ServiceNow logs for more details.`);
        }
    }

})();