const AWS = require("aws-sdk");
const inspector = new AWS.Inspector2({ region: "us-west-2" });
const ecr = new AWS.ECR({ region: "us-west-2" });
const sns = new AWS.SNS({ region: "us-west-2" });
const eventBridge = new AWS.EventBridge({ region: "us-west-2" });
const codepipeline = new AWS.CodePipeline({ region: "us-west-2" });
const ses = new AWS.SES({ region: "us-west-2" });

const pipelineRepoMapping = {
  "test-aws-inspector-result-output": "test-inspector-output",
  "ecrrepositorydashboard-eql8qoibf1cp": "dls-asgard-thor-Dashboard",
  "ecrrepositorylearningpath-plihmoedsnb5": "dls-asgard-thor-Learningpath",
  // Add more mappings as needed
};

var latestImageDigest = "";
var previousImageDigest = "";
var latestImageTag = "";
var previousImageTag = "";
var repositoryARN;
var repositoryName;
var latestTotalCount;
var latestOtherCount;
var previousTotalCount;
var previousOtherCount;
const maxRepoNameLength = 80;
var truncatedRepoName;
var pipelineName;

async function sendApprovalRequestEmail(pipelineName, approvalToken) {
  console.log("approvalToken" + approvalToken);
  console.log("pipelineName: " + pipelineName);
  // Construct the approval links
  const approveLink = `https://lvqkb1ckhk.execute-api.us-west-2.amazonaws.com/approve?token=${approvalToken}&decision=approve&pipelineName=${pipelineName}`;
  const rejectLink = `https://lvqkb1ckhk.execute-api.us-west-2.amazonaws.com/reject?token=${approvalToken}&decision=reject&pipelineName=${pipelineName}`;

  // HTML content for the email
  const htmlContent = `
      <html>
      <body>
          <p>Please <a href="${approveLink}">approve</a> or <a href="${rejectLink}">reject</a> the deployment.</p>
      </body>
      </html>
  `;

  // Send email using Amazon SES
  const params = {
    Source: "megha.garg@comprotechnologies.com",
    Destination: {
      ToAddresses: ["megha.garg@comprotechnologies.com"],
    },
    Message: {
      Body: {
        Html: {
          Charset: "UTF-8",
          Data: htmlContent,
        },
      },
      Subject: {
        Charset: "UTF-8",
        Data: "Approval Request for Deployment",
      },
    },
  };

  try {
    await ses.sendEmail(params).promise();
    console.log("Email sent successfully.");
    return { success: true, message: "Email sent successfully." };
  } catch (error) {
    console.error("Error sending email:", error);
    return { success: false, message: "Error sending email." };
  }
}

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
        findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }],
      },
      maxResults: 100,
      nextToken: nextToken,
    };
    var res = await inspector.listFindings(params).promise();

    findings.push(...res.findings);

    Count += res.findings.length;
    nextToken = res.nextToken;
  } while (nextToken);

  // Extract finding titles from findings
  const findingTitles = findings.map((finding) => finding.title);

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
        findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }],
      },
      maxResults: 100,
      nextToken: nextToken,
    };
    var res = await inspector.listFindings(params).promise();
    totalCount += res.findings.length;
    nextToken = res.nextToken;
  } while (nextToken);
  return totalCount;
}

async function getLatestAndPreviousImageDigest(repositoryName) {
  // Get the list of image details in the repository
  var response = await ecr.describeImages({ repositoryName }).promise();

  // Sort the images by the push timestamp in descending order
  var sortedImages = response.imageDetails.sort(
    (a, b) => b.imagePushedAt - a.imagePushedAt
  );

  // Fetch the digests for the latest and latest-1 images
  latestImageDigest = sortedImages[0].imageDigest;
  previousImageDigest = sortedImages[1] ? sortedImages[1].imageDigest : null;

  latestImageTag = sortedImages[0].imageTags;
  previousImageTag = sortedImages[1] ? sortedImages[1].imageTags : null;

  return {
    latestImageDigest,
    previousImageDigest,
    latestImageTag,
    previousImageTag,
  };
}

async function getPipelineNameByRepoName(repositoryName) {
  pipelineName = pipelineRepoMapping[repositoryName];
  if (!pipelineName) {
    throw new Error(`Pipeline name not found for repo: ${repositoryName}`);
  }
  return pipelineName;
}

async function getApprovalToken(repositoryName) {
  try {
    pipelineName = await getPipelineNameByRepoName(repositoryName);

    const maxRetryAttempts = 3;
    const retryDelayMilliseconds = 60000; // 1 minute in milliseconds

    for (
      let retryAttempt = 1;
      retryAttempt <= maxRetryAttempts;
      retryAttempt++
    ) {
      try {
        const response = await codepipeline
          .getPipelineState({ name: pipelineName })
          .promise();
        // Find the approval stage and get the approval token if it exists
        const approvalStage = response.stageStates.find(
          (stage) => stage.stageName === "Approval"
        );
        if (approvalStage) {
          const approvalToken = approvalStage?.actionStates.find(
            (action) => action.actionName === "Approval"
          )?.latestExecution?.token;
          if (approvalToken) {
            return approvalToken;
          }
        } else {
          console.log("Approval stage not found in the pipeline");
          const errorMessage = `Approval stage not found in the pipeline: ${pipelineName}`;
          const params = {
            TopicArn: "arn:aws:sns:us-west-2:567434252311:Inspector_to_Email",
            Message: errorMessage,
            Subject: `Error in Approving Deployment | Thor | ${latestImageTag}`,
          };
          await sns.publish(params).promise();
          return null;
        }
        console.log(
          `Attempt ${retryAttempt}: Approval token not found. Retrying in 1 minute...`
        );
        await sleep(retryDelayMilliseconds); // Function to sleep for the specified time
      } catch (error) {
        console.error(
          `Attempt ${retryAttempt}: Error getting approval token:`,
          error
        );
        await sleep(retryDelayMilliseconds);
      }
    }
    throw new Error(
      ` ${pipelineName}  : Failed to obtain approval token after ${maxRetryAttempts} attempts.`
    );
  } catch (error) {
    console.error(error);

    const params = {
      TopicArn: "arn:aws:sns:us-west-2:567434252311:Inspector_to_Email",
      Message: `${error}`,
      Subject: `Error in Approving Deployment | Thor | ${latestImageTag}`,
    };
    await sns.publish(params).promise();

    return null; // Return null to indicate error getting pipeline name
  }
}

async function sendApprovalMessage(
  pipelineName,
  approvalToken,
  approvalStatus,
  approvalMessage
) {
  const params = {
    pipelineName,
    stageName: "Approval",
    actionName: "Approval",
    token: approvalToken,
    result: {
      summary: approvalMessage,
      status: approvalStatus, // 'Approved' or 'Rejected'
    },
  };

  return codepipeline.putApprovalResult(params).promise();
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

exports.handler = async (event, context) => {
  var newFindings = [];
  var resolvedFindings = [];
  var messageDetails = {
    Critical: "",
    High: "",
    Medium: "",
    Low: "",
    Other: "",
    Total: "",
    Inspector_Scan_Event_Latest_Image: {},
    NewCriticalFindings: "",
    ResolvedCriticalFindings: "",
    NewHighFindings: "",
    ResolvedHighFindings: "",
  };

  // Retrieve the repository name from the EventBridge event

  messageDetails.Inspector_Scan_Event_Latest_Image = event;

  repositoryARN = event.detail["repository-name"];
  repositoryName = repositoryARN.split("/").pop();

  truncatedRepoName = repositoryName.substring(0, maxRepoNameLength);

  try {
    // Get the image digests for the latest and latest-1 images in the repository
    var {
      latestImageDigest,
      previousImageDigest,
      latestImageTag,
      previousImageTag,
    } = await getLatestAndPreviousImageDigest(repositoryName);

    // Get the vulnerability counts for the latest image
    const {
      Count: latestCriticalCount,
      findingTitles: latestCriticalFindingTitles,
    } = await getInspectorFindingsForImage(latestImageDigest, "CRITICAL");
    const { Count: latestHighCount, findingTitles: latestHighFindingTitles } =
      await getInspectorFindingsForImage(latestImageDigest, "HIGH");
    const { Count: latestMediumCount } = await getInspectorFindingsForImage(
      latestImageDigest,
      "MEDIUM"
    );
    const { Count: latestLowCount } = await getInspectorFindingsForImage(
      latestImageDigest,
      "LOW"
    );
    latestTotalCount = await getInspectorAllFindingsForImage(latestImageDigest);
    latestOtherCount =
      latestTotalCount -
      (latestCriticalCount +
        latestHighCount +
        latestMediumCount +
        latestLowCount);

    console.log(
      "in Main function: " +
        latestCriticalCount +
        "\t" +
        latestHighCount +
        "\t" +
        latestMediumCount +
        "\t" +
        latestLowCount +
        "\t" +
        latestOtherCount +
        "\t" +
        latestTotalCount
    );

    // Compare the counts with the latest-1 image and take appropriate actions
    if (previousImageDigest) {
      const {
        Count: previousCriticalCount,
        findingTitles: previousCriticalFindingTitles,
      } = await getInspectorFindingsForImage(previousImageDigest, "CRITICAL");
      const {
        Count: previousHighCount,
        findingTitles: previousHighFindingTitles,
      } = await getInspectorFindingsForImage(previousImageDigest, "HIGH");
      const { Count: previousMediumCount } = await getInspectorFindingsForImage(
        previousImageDigest,
        "MEDIUM"
      );
      const { Count: previousLowCount } = await getInspectorFindingsForImage(
        previousImageDigest,
        "LOW"
      );
      previousTotalCount = await getInspectorAllFindingsForImage(
        previousImageDigest
      );
      previousOtherCount =
        previousTotalCount -
        (previousCriticalCount +
          previousHighCount +
          previousMediumCount +
          previousLowCount);

      console.log(
        "in Main function: " +
          previousCriticalCount +
          "\t" +
          previousHighCount +
          "\t" +
          previousMediumCount +
          "\t" +
          previousLowCount +
          "\t" +
          previousOtherCount +
          "\t" +
          previousTotalCount
      );

      newCriticalFindings = latestCriticalFindingTitles.filter(
        (title) => !previousCriticalFindingTitles.includes(title)
      );
      console.log("newCriticalFindings : " + newCriticalFindings);
      console.log("newCriticalFindinglength: " + newCriticalFindings.length);
      resolvedCriticalFindings = previousCriticalFindingTitles.filter(
        (title) => !latestCriticalFindingTitles.includes(title)
      );
      console.log("resolvedCriticalFindings:  " + resolvedCriticalFindings);

      //high
      newHighFindings = latestHighFindingTitles.filter(
        (title) => !previousHighFindingTitles.includes(title)
      );
      console.log("newHighFindings: " + newHighFindings);
      resolvedHighFindings = previousHighFindingTitles.filter(
        (title) => !latestHighFindingTitles.includes(title)
      );
      console.log("resolvedHighFindings: " + resolvedHighFindings);

      messageDetails.Critical = `${latestCriticalCount} (Change = ${
        latestCriticalCount - previousCriticalCount
      })`;
      messageDetails.High = `${latestHighCount} (Change = ${
        latestHighCount - previousHighCount
      })`;
      messageDetails.Medium = `${latestMediumCount} (Change = ${
        latestMediumCount - previousMediumCount
      })`;
      messageDetails.Low = `${latestLowCount} (Change = ${
        latestLowCount - previousLowCount
      })`;
      messageDetails.Other = `${latestOtherCount} (Change = ${
        latestOtherCount - previousOtherCount
      })`;
      messageDetails.Total = `${latestTotalCount} (Change = ${
        latestTotalCount - previousTotalCount
      })`;
      messageDetails.latestCriticalFindingTitles = `${latestCriticalFindingTitles.join(
        ", "
      )}`;
      messageDetails.previousCriticalFindingTitles = `${previousCriticalFindingTitles.join(
        ", "
      )}`;
      //high titles
      messageDetails.latestHighFindingTitles = `${latestHighFindingTitles.join(
        ", "
      )}`;
      messageDetails.previousHighFindingTitles = `${previousHighFindingTitles.join(
        ", "
      )}`;
      if (newCriticalFindings.length > 0) {
        messageDetails.CriticalStatus = "NEW_CRITICAL_VULNERABILITY_ADDED";
        messageDetails.NewCriticalFindings = `${newCriticalFindings.join(
          ", "
        )}`;
        messageDetails.ResolvedCriticalFindings = `${resolvedCriticalFindings.join(
          ", "
        )}`;
      } else {
        messageDetails.CriticalStatus = "NO_NEW_CRITICAL_VULNERABILITY_ADDED";
        delete messageDetails.NewCriticalFindings;
        delete messageDetails.ResolvedCriticalFindings;
      }
      //high
      if (newHighFindings.length > 0) {
        messageDetails.HighStatus = "NEW_HIGH_VULNERABILITY_ADDED";
        messageDetails.NewHighFindings = `${newHighFindings.join(", ")}`;
        messageDetails.ResolvedHighFindings = `${resolvedHighFindings.join(
          ", "
        )}`;
      } else {
        messageDetails.HighStatus = "NO_NEW_HIGH_VULNERABILITY_ADDED";
        delete messageDetails.NewHighFindings;
        delete messageDetails.ResolvedHighFindings;
      }

      var table = Object.entries(messageDetails)
        .map(([key, value]) => {
          if (typeof value === "object") {
            value = JSON.stringify(value);
          }

          if (
            (key === "Inspector_Scan_Event_Latest_Image") |
            (key === "latestCriticalFindingTitles") |
            (key === "previousCriticalFindingTitles") |
            (key === "latestHighFindingTitles") |
            (key === "previousHighFindingTitles") |
            (key === "CriticalStatus") |
            (key === "HighStatus") | 
            (key === "NewCriticalFindings") |
            (key === "ResolvedCriticalFindings") | 
            (key === "NewHighFindings") | 
            (key === "ResolvedHighFindings")
          ) {
            key = "\n" + `${key}`;
          }

          return `${key} : ${value}`;
        })
        .join("\n");

      // Publish the comparison result to the SNS topic
      const params = {
        TopicArn: "arn:aws:sns:us-west-2:567434252311:Inspector_to_Email",
        Message: table,
        Subject: `${truncatedRepoName} | Thor | ${latestImageTag}`,
      };
      await sns.publish(params).promise();

      // get an approval token and send an Email to manually get the approval and rejection using API
      const approvalToken = await getApprovalToken(repositoryName);
      console.log("approval token: " + approvalToken);
      if (approvalToken !== null) {
        const emailResult = await sendApprovalRequestEmail(
          pipelineName,
          approvalToken
        );

        if (emailResult.success) {
          return { statusCode: 200, body: emailResult.message };
        } else {
          return { statusCode: 500, body: emailResult.message };
        }
      }
      // if (messageDetails.Status == 'NO_NEW_CRITICAL_VULNERABILITY_ADDED') {
      //   const approvalStatus = 'Approved';
      //   const approvalMessage = 'Deployment is approved.';
      //   const approvalToken = await getApprovalToken(repositoryName);
      //   if (approvalToken !== null) {
      //     await sendApprovalMessage(pipelineName, approvalToken, approvalStatus, approvalMessage);
      //     const params = {
      //       TopicArn: 'arn:aws:sns:us-west-2:567434252311:Inspector_to_Email',
      //       Message: approvalMessage,
      //       Subject: `${truncatedRepoName} | Thor | ${latestImageTag}`,
      //     };
      //     await sns.publish(params).promise();
      //   }
      // }
      // else {
      //   const approvalStatus = 'Rejected';
      //   const approvalMessage = `Deployment is Rejected as new Critical Vurnerabilities are added with the latest Image tag ${latestImageTag}`;
      //   const approvalToken = await getApprovalToken(repositoryName);
      //   if (approvalToken !== null) {
      //     await sendApprovalMessage(pipelineName, approvalToken, approvalStatus, approvalMessage);
      //     const params = {
      //       TopicArn: 'arn:aws:sns:us-west-2:567434252311:Inspector_to_Email',
      //       Message: approvalMessage,
      //       Subject: `${truncatedRepoName} | Thor | ${latestImageTag}`,
      //     };
      //     await sns.publish(params).promise();
      //   }
      // }
    } else {
      messageDetails.Critical = latestCriticalCount;
      messageDetails.High = latestHighCount;
      messageDetails.Medium = latestMediumCount;
      messageDetails.Low = latestLowCount;
      messageDetails.Other = latestOtherCount;
      messageDetails.Total = latestTotalCount;

      // messageDetails.OverallStatus = 'There is only one image present for the repository. No Previous image found for Comparision.';

      var table = Object.entries(messageDetails)
        .map(([key, value]) => {
          if (typeof value === "object") {
            value = JSON.stringify(value);
          }

          if (key === "Inspector_Scan_Event_Latest_Image") {
            key = "\n" + key;
          }

          return `${key} : ${value}`;
        })
        .join("\n");

      // Publish the comparison result to the SNS topic
      const params = {
        TopicArn: "arn:aws:sns:us-west-2:567434252311:Inspector_to_Email",
        Message: table,
        Subject: `${truncatedRepoName} | Thor | ${latestImageTag}`,
      };
      await sns.publish(params).promise();
    }

    // Return a success response
    return {
      statusCode: 200,
      body: "Vulnerability comparison compare.",
    };
  } catch (error) {
    console.error("Error:", error);

    const params = {
      TopicArn: "arn:aws:sns:us-west-2:567434252311:Inspector_to_Email",
      Message: `Repository Name: ${repositoryName}\n\nError while exceuting comparision:\n ${JSON.stringify(
        error
      )}`,
      Subject: `Error in Inspector Scan | Thor | ${latestImageTag}`,
    };
    await sns.publish(params).promise();
    throw error;
  }
};
