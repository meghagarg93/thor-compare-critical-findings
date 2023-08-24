const AWS = require('aws-sdk');
const inspector = new AWS.Inspector2({ region: 'us-west-2' });
const ecr = new AWS.ECR({ region: 'us-west-2' });
const sns = new AWS.SNS({ region: 'us-west-2' });
const eventBridge = new AWS.EventBridge({ region: 'us-west-2' });

var latestImageDigest = '';
var previousImageDigest = '';
var latestImageTag = '';
var previousImageTag = '';
var repositoryARN;
var repositoryName;
var latestTotalCount;
var latestOtherCount;
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


async function getInspectorFindingsForImage(imageDigest, severity) {
  // Retrieve the findings for the image from AWS Inspector

  var nextToken = undefined;
  var findings = []; // Array to store findings
  var Count = 0;
  do {
    var params = {
      filterCriteria: {
        ecrImageHash: [{ comparison: "EQUALS", value: imageDigest }],
        severity: [{ comparison: "EQUALS", value: severity }],
        findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }]
      },
      maxResults: 100,
      nextToken: nextToken
    };
    var res = await inspector.listFindings(params).promise();

    findings.push(...res.findings);

    Count += res.findings.length;
    nextToken = res.nextToken;
  }
  while (nextToken)

  // Extract finding titles from findings
  const findingTitles = findings.map(finding => finding.title);

  return { Count, findingTitles };
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

async function sendEventToEventBridge(repositoryName, imageTag, status) {
  const event = {
    Source: "lambda", // Replace with your event source
    DetailType: "ImageDeployment",
    Detail: JSON.stringify({
      repositoryName: repositoryName,
      imageTag: imageTag,
      status: status
    })
  };

  const params = {
    Entries: [event],
  };

  console.log("event: " + JSON.stringify(event));

  const result = await eventBridge.putEvents(params).promise(); // Wait for the promise to resolve
  return result;
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
    // latestFindingsInfo = await getInspectorFindingsForImage(latestImageDigest, "CRITICAL");

    const { Count: latestCriticalCount, findingTitles: latestCriticalFindingTitles } = await getInspectorFindingsForImage(latestImageDigest, "CRITICAL");
    const { Count: latestHighCount } = await getInspectorFindingsForImage(latestImageDigest, "HIGH");
    const { Count: latestMediumCount } = await getInspectorFindingsForImage(latestImageDigest, "MEDIUM");
    const { Count: latestLowCount } = await getInspectorFindingsForImage(latestImageDigest, "LOW");

    // latestCriticalCount = await getInspectorFindingsForImage(latestImageDigest, "CRITICAL");
    // latestHighCount = await getInspectorFindingsForImage(latestImageDigest, "HIGH");
    // latestMediumCount = await getInspectorFindingsForImage(latestImageDigest, "MEDIUM");
    // latestLowCount = await getInspectorFindingsForImage(latestImageDigest, "LOW");
    latestTotalCount = await getInspectorAllFindingsForImage(latestImageDigest);
    latestOtherCount = latestTotalCount - (latestCriticalCount + latestHighCount + latestMediumCount + latestLowCount);

    console.log("in Main function: " + latestCriticalCount + "\t" + latestHighCount + "\t" + latestMediumCount + "\t" + latestLowCount + "\t" + latestOtherCount + "\t" + latestTotalCount)

    // Compare the counts with the latest-1 image and take appropriate actions
    if (previousImageDigest) {

      const { Count: previousCriticalCount, findingTitles: previousCriticalFindingTitles } = await getInspectorFindingsForImage(previousImageDigest, "CRITICAL");
      const { Count: previousHighCount } = await getInspectorFindingsForImage(previousImageDigest, "HIGH");
      const { Count: previousMediumCount } = await getInspectorFindingsForImage(previousImageDigest, "MEDIUM");
      const { Count: previousLowCount } = await getInspectorFindingsForImage(previousImageDigest, "LOW");


      // previousCriticalCount = await getInspectorFindingsForImage(previousImageDigest, "CRITICAL");
      // previousHighCount = await getInspectorFindingsForImage(previousImageDigest, "HIGH");
      // previousMediumCount = await getInspectorFindingsForImage(previousImageDigest, "MEDIUM");
      // previousLowCount = await getInspectorFindingsForImage(previousImageDigest, "LOW");
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


      const newFindings = latestCriticalFindingTitles.filter(title => !previousCriticalFindingTitles.includes(title));
      const resolvedFindings = previousCriticalFindingTitles.filter(title => !latestCriticalFindingTitles.includes(title));

      messageDetails.Critical = `${latestCriticalCount} (Change = ${latestCriticalCount - previousCriticalCount})`;
      messageDetails.High = `${latestHighCount} (Change = ${latestHighCount - previousHighCount})`;
      messageDetails.Medium = `${latestMediumCount} (Change = ${latestMediumCount - previousMediumCount})`;
      messageDetails.Low = `${latestLowCount} (Change = ${latestLowCount - previousLowCount})`;
      messageDetails.Other = `${latestOtherCount} (Change = ${latestOtherCount - previousOtherCount})`;
      messageDetails.Total = `${latestTotalCount} (Change = ${latestTotalCount - previousTotalCount})`;
      messageDetails.latestCriticalFindingTitles = `${latestCriticalFindingTitles.join(', ')}`
      messageDetails.previousCriticalFindingTitles = `${previousCriticalFindingTitles.join(', ')}`

      if (newFindings > 0) {
        messageDetails.Staus = "NEW_CRITICAL_VULNERABILITY_ADDED"
        messageDetails.NewFindings = `${newFindings.join(', ')}`
        //send message to SNS that deployment event is not sent
        const params = {
          TopicArn: 'arn:aws:sns:us-west-2:567434252311:Inspector_to_Email',
          Message: "Image deployment event is not triggered as new vulnerabilities are added",
          Subject: `${truncatedRepoName} | Thor | ${latestImageTag}`,
        };

      }
      else {
        messageDetails.Status = "NO_NEW_CRITICAL_VULNERABILITY_ADDED"
        delete messageDetails.newFindings;
        await sendEventToEventBridge(repositoryName, latestImageTag, messageDetails.Status);
      }


      var table = Object.entries(messageDetails)
        .map(([key, value]) => {
          if (typeof value === 'object') {
            value = JSON.stringify(value);
          }

          if (key === 'Inspector_Scan_Event_Latest_Image' | key === 'latestCriticalFindingTitles' | key === 'previousCriticalFindingTitles' | key === 'Status' | key === 'NEW_CRITICAL_VULNERABILITY_ADDED') {
            key = '\n' + `${key}`;
          }

          return `${key} : ${value}`;
        })
        .join('\n');

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

      // Publish the comparison result to the SNS topic
      const params = {
        TopicArn: 'arn:aws:sns:us-west-2:567434252311:Inspector_to_Email',
        Message: table,
        Subject: `${truncatedRepoName} | Thor | ${latestImageTag}`,
      };


      await sns.publish(params).promise();
    }

    // await sendEventToEventBridge(truncatedRepoName, latestImageTag, messageDetails.Status);

    // Return a success response
    return {
      statusCode: 200,
      body: 'Vulnerability comparison compare.',
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