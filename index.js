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
var criticalCount;
var highCount;
var mediumCount;
var lowCount;
var latestCriticalCount;
var latestHighCount;
var latestMediumCount;
var latestLowCount;
var latestCount;
var previousCriticalCount;
var previousHighCount;
var previousLowCount;
var previousMediumCount;
var previousCount;


var messageDetails = {
  OverallStatus: '',
  New_Critical_Vurnerabilities: '',
  New_High_Vurnerabilities: '',
  New_Medium_Vurnerabilites: '',
  New_Low_Vurnerabilities: '',
  New_Total_Vurnerabilities: '',
  Inspector_Scan_Event_Latest_Image: {}
};


async function getInspectorCriticalFindingsForImage(imageDigest) {
  // Retrieve the findings for the image from AWS Inspector

  var paramsCritical = {
    filterCriteria: {
      ecrImageHash: [{ comparison: "EQUALS", value: imageDigest }],
      severity: [{ comparison: "EQUALS", value: "CRITICAL" }],
      findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }]
    },
    maxResults: 100,
  }
  var resCritical = await inspector.listFindings(paramsCritical).promise();
  criticalCount = resCritical.findings.length;

  return criticalCount;
}

async function getInspectorHighFindingsForImage(imageDigest) {
  // Retrieve the findings for the image from AWS Inspector

  var paramsHigh = {
    filterCriteria: {
      ecrImageHash: [{ comparison: "EQUALS", value: imageDigest }],
      severity: [{ comparison: "EQUALS", value: "HIGH" }],
      findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }]
    },
    maxResults: 100,
  }
  var resHigh = await inspector.listFindings(paramsHigh).promise();
  highCount = resHigh.findings.length;

  return highCount;
}
async function getInspectorMediumFindingsForImage(imageDigest) {
  // Retrieve the findings for the image from AWS Inspector

  var paramsMedium = {
    filterCriteria: {
      ecrImageHash: [{ comparison: "EQUALS", value: imageDigest }],
      severity: [{ comparison: "EQUALS", value: "MEDIUM" }],
      findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }]
    },
    maxResults: 100,
  }
  var resMedium = await inspector.listFindings(paramsMedium).promise();
  mediumCount = resMedium.findings.length;

  return mediumCount;
}
async function getInspectorLowFindingsForImage(imageDigest) {
  // Retrieve the findings for the image from AWS Inspector

  var paramsLow = {
    filterCriteria: {
      ecrImageHash: [{ comparison: "EQUALS", value: imageDigest }],
      severity: [{ comparison: "EQUALS", value: "LOW" }],
      findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }]
    },
    maxResults: 100,
  }
  var resLow = await inspector.listFindings(paramsLow).promise();
  lowCount = resLow.findings.length;

  return lowCount;
}

// async function countCriticalVulnerabilities(imageDigest) {
//   // Get the vulnerability findings for the image
//   var findings = await getInspectorFindingsForImage(imageDigest);

//   // Calculate the count of critical vulnerabilities
//   return findings.length;
// }

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

  try {
    // Get the image digests for the latest and latest-1 images in the repository
    var { latestImageDigest, previousImageDigest, latestImageTag, previousImageTag } = await getLatestAndPreviousImageDigest(repositoryName);

    // Get the vulnerability counts for the latest image
    latestCriticalCount = await getInspectorCriticalFindingsForImage(latestImageDigest);
    latestHighCount = await getInspectorHighFindingsForImage(latestImageDigest);
    latestMediumCount = await getInspectorMediumFindingsForImage(latestImageDigest);
    latestLowCount = await getInspectorLowFindingsForImage(latestImageDigest);
    console.log("in Main function: " + latestCriticalCount + "\t" + latestHighCount + "\t" + latestMediumCount + "\t" + latestLowCount)

    latestCount = latestCriticalCount + latestHighCount + latestMediumCount + latestLowCount;

    console.log("latestCount: " + latestCount);
    // Compare the counts with the latest-1 image and take appropriate actions
    if (previousImageDigest) {
      previousCriticalCount = await getInspectorCriticalFindingsForImage(previousImageDigest);
      previousHighCount = await getInspectorHighFindingsForImage(previousImageDigest);
      previousMediumCount = await getInspectorMediumFindingsForImage(previousImageDigest);
      previousLowCount = await getInspectorLowFindingsForImage(previousImageDigest);
      console.log("in Main function: " + previousCriticalCount + "\t" + previousHighCount + "\t" + previousMediumCount + "\t" + previousLowCount)
      previousCount = previousCriticalCount + previousHighCount + previousMediumCount + previousLowCount;


      console.log("previousCount: " + previousCount);



      if (latestCriticalCount > previousCriticalCount) {
        messageDetails.OverallStatus = 'Fail !! Vurnerability has increased with the new deployment';
      } else if (latestCriticalCount < previousCriticalCount) {
        messageDetails.OverallStatus = 'The latest image has fewer critical vulnerabilities than the previous image.';
      } else {
        messageDetails.OverallStatus = 'No change in Critical vulnerabilities count';
      }


      messageDetails.New_Critical_Vurnerabilities = latestCriticalCount - previousCriticalCount;
      messageDetails.New_High_Vurnerabilities = latestHighCount - previousHighCount;
      messageDetails.New_Medium_Vurnerabilites = latestMediumCount - previousMediumCount;
      messageDetails.New_Low_Vurnerabilities = latestLowCount - previousLowCount;
      messageDetails.New_Total_Vurnerabilities = latestCount - previousCount;

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
        Subject: `[${repositoryName}] | [Thor] | [${latestImageTag}]`,
      };


      await sns.publish(params).promise();
    }
    else {

      messageDetails.New_Critical_Vurnerabilities = latestCriticalCount;
      messageDetails.New_High_Vurnerabilities = latestHighCount;
      messageDetails.New_Medium_Vurnerabilites = latestMediumCount;
      messageDetails.New_Low_Vurnerabilities = latestLowCount;
      messageDetails.New_Total_Vurnerabilities = latestCount;

      console.log("message: " + JSON.stringify(messageDetails))
      messageDetails.OverallStatus = 'There is only one image present for the repository. No Previous image found';

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
        Subject: `[${repositoryName}] | [Thor] | [${latestImageTag}]`,
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
    // Handle any errors that occurred during processing
    throw error;
  }
};