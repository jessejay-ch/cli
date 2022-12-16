import { Log } from 'sarif';
import * as Debug from 'debug';
import config from '../../config';
import { makeRequest } from '../../request';
import { getAuthHeader } from '../../api-token';
import { AuthFailedError, ValidationError } from '../../errors';
import { getCodeReportDisplayedOutput } from './format/output-format';

const debug = Debug('snyk-code-upload-report');

type CodeUploadArgs = {
  org: string | null;
  results: Log;
  projectName: string;
};

export async function uploadCodeReport(args: CodeUploadArgs): Promise<string> {
  debug('Starting Code report upload');

  const uploadResultsRes = await uploadResults(args);

  return getCodeReportDisplayedOutput(
    `${config.ROOT}/org/${args.org}/project/${uploadResultsRes.projectPublicId}`,
  );
}

type UploadResultsOutput = {
  projectPublicId: string;
};

async function uploadResults({
  org,
  results,
  projectName,
}: CodeUploadArgs): Promise<UploadResultsOutput> {
  const { res, body } = await makeRequest({
    method: 'POST',
    url: `${config.API}/sast-cli-share-results`,
    json: true,
    qs: { org: org ?? config.org },
    headers: {
      authorization: getAuthHeader(),
    },
    body: {
      projectName,
      results,
    },
  });

  if (res.statusCode === 401) {
    throw AuthFailedError();
  } else if (res.statusCode! < 200 || res.statusCode! > 299) {
    throw new ValidationError(
      res.body.error ?? 'An error occurred, please contact Snyk support',
    );
  }

  return { projectPublicId: body.projectPublicId };
}
