const AWS = require('aws-sdk');
const inspector = new AWS.Inspector2({ region: 'us-west-2' });
const ecr = new AWS.ECR({ region: 'us-west-2' });
const sns = new AWS.SNS({ region: 'us-west-2' });

var latestImageDigest = '';
var previousImageDigest = '';
var latestImageTag = '';
var previousImageTag = '';
var repositoryARN;
var repositoryName;
var latestCriticalCount;
var latestHighCount;
var latestMediumCount;
var latestLowCount;
var latestTotalCount;
var latestOtherCount;
var previousCriticalCount;
var previousHighCount;
var previousLowCount;
var previousMediumCount;
var previousTotalCount;
var previousOtherCount;
const maxRepoNameLength = 80;
var truncatedRepoName;

var messageDetails = {
  Critical: '',
  High: '',
  Medium: '',
  Low: '',
  Other: '',
  Total: '',
  Inspector_Scan_Event_Latest_Image: {}
};


async function getInspectorCriticalFindingsForImage(imageDigest) {
  // Retrieve the findings for the image from AWS Inspector

  var nextToken = undefined;
  var criticalCount = 0;
  do {
    var params = {
      filterCriteria: {
        ecrImageHash: [{ comparison: "EQUALS", value: imageDigest }],
        severity: [{ comparison: "EQUALS", value: "CRITICAL" }],
        findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }]
      },
      maxResults: 100,
      nextToken: nextToken
    };
    var res = await inspector.listFindings(params).promise();
    criticalCount += res.findings.length;
    nextToken = res.nextToken;
  }
  while (nextToken)
  return criticalCount;
}

async function getInspectorHighFindingsForImage(imageDigest) {
  // Retrieve the findings for the image from AWS Inspector

  var nextToken = undefined;
  var highCount = 0;
  do {
    var params = {
      filterCriteria: {
        ecrImageHash: [{ comparison: "EQUALS", value: imageDigest }],
        severity: [{ comparison: "EQUALS", value: "HIGH" }],
        findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }]
      },
      maxResults: 100,
      nextToken: nextToken
    };
    var res = await inspector.listFindings(params).promise();
    highCount += res.findings.length;
    nextToken = res.nextToken;
  }
  while (nextToken)
  return highCount;
}

async function getInspectorMediumFindingsForImage(imageDigest) {
  // Retrieve the findings for the image from AWS Inspector
  var nextToken = undefined;
  var mediumCount = 0;
  do {
    var params = {
      filterCriteria: {
        ecrImageHash: [{ comparison: "EQUALS", value: imageDigest }],
        severity: [{ comparison: "EQUALS", value: "MEDIUM" }],
        findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }]
      },
      maxResults: 100,
      nextToken: nextToken
    };
    var res = await inspector.listFindings(params).promise();
    mediumCount += res.findings.length;
    nextToken = res.nextToken;
  }
  while (nextToken)
  return mediumCount;
}
async function getInspectorLowFindingsForImage(imageDigest) {
  // Retrieve the findings for the image from AWS Inspector
  var nextToken = undefined;
  var lowCount = 0;
  do {
    var params = {
      filterCriteria: {
        ecrImageHash: [{ comparison: "EQUALS", value: imageDigest }],
        severity: [{ comparison: "EQUALS", value: "LOW" }],
        findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }]
      },
      maxResults: 100,
      nextToken: nextToken
    };
    var res = await inspector.listFindings(params).promise();
    lowCount += res.findings.length;
    nextToken = res.nextToken;
  }
  while (nextToken)
  return lowCount;
}

async function getInspectorAllFindingsForImage(imageDigest) {
  // Retrieve the findings for the image from AWS Inspector
  var nextToken = undefined;
  var totalCount = 0;
  do {
    var params = {
      filterCriteria: {
        ecrImageHash: [{ comparison: "EQUALS", value: imageDigest }],
        findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }]
      },
      maxResults: 100,
      nextToken: nextToken
    };
    var res = await inspector.listFindings(params).promise();
    totalCount += res.findings.length;
    nextToken = res.nextToken;
  }
  while (nextToken);
  return totalCount;
}

async function getLatestAndPreviousImageDigest(repositoryName) {
  // Get the list of image details in the repository
  var response = await ecr.describeImages({ repositoryName }).promise();

  // Sort the images by the push timestamp in descending order
  var sortedImages = response.imageDetails.sort((a, b) => b.imagePushedAt - a.imagePushedAt);

  // Fetch the digests for the latest and latest-1 images
  latestImageDigest = sortedImages[0].imageDigest;
  previousImageDigest = sortedImages[1] ? sortedImages[1].imageDigest : null;

  latestImageTag = sortedImages[0].imageTags;
  previousImageTag = sortedImages[1] ? sortedImages[1].imageTags : null;

  return { latestImageDigest, previousImageDigest, latestImageTag, previousImageTag };

}

exports.handler = async (event, context) => {
  // Retrieve the repository name from the EventBridge event

  messageDetails.Inspector_Scan_Event_Latest_Image = event;

  repositoryARN = event.detail['repository-name'];
  repositoryName = repositoryARN.split("/").pop();

  truncatedRepoName = repositoryName.substring(0, maxRepoNameLength);

  try {
    // Get the image digests for the latest and latest-1 images in the repository
    var { latestImageDigest, previousImageDigest, latestImageTag, previousImageTag } = await getLatestAndPreviousImageDigest(repositoryName);

    // Get the vulnerability counts for the latest image

    latestCriticalCount = await getInspectorCriticalFindingsForImage(latestImageDigest);
    latestHighCount = await getInspectorHighFindingsForImage(latestImageDigest);
    latestMediumCount = await getInspectorMediumFindingsForImage(latestImageDigest);
    latestLowCount = await getInspectorLowFindingsForImage(latestImageDigest);
    latestTotalCount = await getInspectorAllFindingsForImage(latestImageDigest);
    latestOtherCount = latestTotalCount - (latestCriticalCount + latestHighCount + latestMediumCount + latestLowCount);

    console.log("in Main function: " + latestCriticalCount + "\t" + latestHighCount + "\t" + latestMediumCount + "\t" + latestLowCount + "\t" + latestOtherCount + "\t" + latestTotalCount)

    // Compare the counts with the latest-1 image and take appropriate actions
    if (previousImageDigest) {
      previousCriticalCount = await getInspectorCriticalFindingsForImage(previousImageDigest);
      previousHighCount = await getInspectorHighFindingsForImage(previousImageDigest);
      previousMediumCount = await getInspectorMediumFindingsForImage(previousImageDigest);
      previousLowCount = await getInspectorLowFindingsForImage(previousImageDigest);
      previousTotalCount = await getInspectorAllFindingsForImage(previousImageDigest);
      previousOtherCount = previousTotalCount - (previousCriticalCount + previousHighCount + previousMediumCount + previousLowCount);

      console.log("in Main function: " + previousCriticalCount + "\t" + previousHighCount + "\t" + previousMediumCount + "\t" + previousLowCount + "\t" + previousOtherCount + "\t" + previousTotalCount);

      // if (latestCriticalCount > previousCriticalCount) {
      //   messageDetails.OverallStatus = 'Fail !! Critical Vulnerabilities have increased with the new deployment.';
      // } else if (latestCriticalCount < previousCriticalCount) {
      //   messageDetails.OverallStatus = 'Pass !! Critical Vulnerabilities have reduced with the new deployment.';
      // } else {
      //   messageDetails.OverallStatus = 'No change in Critical vulnerabilities Count.';
      // }

      messageDetails.Critical = `${latestCriticalCount} (Change = ${latestCriticalCount - previousCriticalCount})`;
      messageDetails.High = `${latestHighCount} (Change = ${latestHighCount - previousHighCount})`;
      messageDetails.Medium = `${latestMediumCount} (Change = ${latestMediumCount - previousMediumCount})`;
      messageDetails.Low = `${latestLowCount} (Change = ${latestLowCount - previousLowCount})`;
      messageDetails.Other = `${latestOtherCount} (Change = ${latestOtherCount - previousOtherCount})`;
      messageDetails.Total = `${latestTotalCount} (Change = ${latestTotalCount - previousTotalCount})`;

      var table = Object.entries(messageDetails)
        .map(([key, value]) => {
          if (typeof value === 'object') {
            value = JSON.stringify(value);
          }

          if (key === 'Inspector_Scan_Event_Latest_Image') {
            key = '\n' + `${key}`;
          }

          return `${key} : ${value}`;
        })
        .join('\n');
      console.log(table);

      // Publish the comparison result to the SNS topic

      const params = {
        TopicArn: 'arn:aws:sns:us-west-2:567434252311:Inspector_to_Email',
        Message: table,
        Subject: `${truncatedRepoName} | Thor | ${latestImageTag}`,
      };


      await sns.publish(params).promise();
    }
    else {

      messageDetails.Critical = latestCriticalCount;
      messageDetails.High = latestHighCount;
      messageDetails.Medium = latestMediumCount;
      messageDetails.Low = latestLowCount;
      messageDetails.Other = latestOtherCount;
      messageDetails.Total = latestTotalCount;

      console.log("message: " + JSON.stringify(messageDetails))
      // messageDetails.OverallStatus = 'There is only one image present for the repository. No Previous image found for Comparision.';

      var table = Object.entries(messageDetails)
        .map(([key, value]) => {
          if (typeof value === 'object') {
            value = JSON.stringify(value);
          }

          if (key === 'Inspector_Scan_Event_Latest_Image') {
            key = '\n' + key;
          }

          return `${key} : ${value}`;
        })
        .join('\n');
      console.log(table);

      // Publish the comparison result to the SNS topic

      const params = {
        TopicArn: 'arn:aws:sns:us-west-2:567434252311:Inspector_to_Email',
        Message: table,
        Subject: `${truncatedRepoName} | Thor | ${latestImageTag}`,
      };


      await sns.publish(params).promise();
    }

    // Return a success response
    return {
      statusCode: 200,
      body: 'Vulnerability comparison compvare.',
    };
  } catch (error) {
    console.error('Error:', error);

    const params = {
      TopicArn: 'arn:aws:sns:us-west-2:567434252311:Inspector_to_Email',
      Message: `Repository Name: ${repositoryName}\n\nError while exceuting comparision:\n ${JSON.stringify(error)}`,
      Subject: `Error in Inspector Scan | Thor | ${latestImageTag}`
    };
    await sns.publish(params).promise();
    throw error;
  }
};