const AWS = require("aws-sdk");
const axios = require("axios");
const { Resolver } = require("dns");
const { response } = require("express");
const rp = require("request-promise");

//Initialization of keys
const accessKeyId = "";
const secretAccessKey = "";

//Connection
AWS.config.update({
  accessKeyId,
  secretAccessKey,
  region: "us-east-1",
});

const route53 = new AWS.Route53();
const route53domains = new AWS.Route53Domains();
const s3 = new AWS.S3();
const cloudfront = new AWS.CloudFront();
const resolver = new Resolver();

//Global Variables
let hosted_zones = [];
let resource_records = [];
let vulnerable_domains = [];
let maxSize;

async function listHostedZones() {
  try {
    const res = await route53.listHostedZones().promise();
    hosted_zones.push(res.HostedZones);
    maxSize = res.HostedZones[0].ResourceRecordSetCount;
  } catch (err) {
    console.error(err);
  }
  //To check hosted zones
  // console.log("Hosted Zones:", hosted_zones);
}

async function listResourceRecordSets(recordType) {
  const params = {
    HostedZoneId: hosted_zones[0][0].Id /* required */,
    StartRecordName: "_",
    StartRecordType: recordType,
  };
  const res = await route53.listResourceRecordSets(params).promise();
  res.ResourceRecordSets.map((record) => resource_records.push(record));
  let nextRecordName = res.NextRecordName;
  let nextRecordType = res.NextRecordType;
  let isTruncated = res.IsTruncated;
  //As in AWS, maxSize = 100
  while (isTruncated && resource_records.length <= maxSize) {
    const params1 = {
      HostedZoneId: hosted_zones[0][0].Id,
      StartRecordName: nextRecordName,
      StartRecordType: nextRecordType,
    };

    const res = await route53.listResourceRecordSets(params1).promise();
    res.ResourceRecordSets.map((record) => resource_records.push(record));
    nextRecordName = res.NextRecordName;
    nextRecordType = res.NextRecordType;
    isTruncated = res.IsTruncated;
  }
  // To check Resource Records
  //console.log(resource_records);
}

const fetchData = async (url, name) => {
  const res = await rp(url)
    .then(function (html) {
      // //success!
      // console.log(html);
    })
    .catch(function (err) {
      // ErrorHandler
      // Cloundfront URLs with 404 & No suck bucket text will be declared vulnerable
      if (err.statusCode === 404 && err.error.includes("NoSuchBucket")) {
        console.log(
          name + " is vulnerable to subdomain takeover with cloudfront url:",
          url
        );
        vulnerable_domains.push({ Subdomain: name, Cloudfront: url });
      } else {
        console.log("Safe domain; No takeover found on", url);
      }
    });
};

async function missingCloudfrontCname() {
  const res = await Promise.all(
    resource_records.map(async (record) => {
      if (
        record.Type === "CNAME" &&
        record.ResourceRecords[0].Value.includes("cloudfront.net")
      ) {
        //To check suspected URLs
        console.log(record);
        console.log(
          "Checking if  " + record.Name + "is vulnerable to takeover"
        );
        //URL of cloudfront
        const url = "https://" + record.ResourceRecords[0].Value;
        //Fetch HTML of the page via passing cloudfront url and subdomain
        const fetch = await fetchData(url, record.Name);
      }
    })
  );
}

async function missingS3Cname() {
  const res = await Promise.all(
    resource_records.map(async (record) => {
      if (
        record.Type === "CNAME" &&
        record.ResourceRecords[0].Value.includes("amazonaws.com") &&
        record.ResourceRecords.includes(".s3-website.")
      ) {
        console.log(
          "Checking if " + record.Name + " is Vulnerable to takeover"
        );

        const url = "http://" + record.ResourceRecords[0].Value;
        //Fetch HTML of the page via passing cloudfront url and subdomain
        const fetch = await fetchData(url);
      }
    })
  );
}

async function missingElasticBeanStalkCname() {
  const res = await Promise.all(
    resource_records.map(async (record) => {
      if (
        record.Type === "CNAME" &&
        record.ResourceRecords[0].Value.includes("elasticbeanstalk.com")
      ) {
        console.log(
          "Checking if " + record.Name + " is Vulnerable to takeover"
        );

        const url = "http://" + record.ResourceRecords[0].Value;
        //Fetch HTML of the page via passing cloudfront url and subdomain
        const fetch = await fetchData(url);
      }
    })
  );
}

async function run() {
  //<!--GET HOSTED ZONES-->
  const host = await listHostedZones();
  // console.log(hosted_zones);
  if (!hosted_zones[0][0].Config.PrivateZone) {
    console.log(
      "Searching for CloudFront Alias records in hosted zone",
      hosted_zones[0][0].Name
    );
  }
  const records_set = await listResourceRecordSets("CNAME");

  //scans Amazon Route53 CNAME records to identify CloudFront distributions with missing S3 origin
  console.log(
    "Scanning Amazon Route53 CNAME records to identify CloudFront distributions with missing S3 origin:"
  );
  const vuln_cloudfront = await missingCloudfrontCname();
  //scans AWS Route53 for S3 CNAMES vulnerable to takeover
  console.log(
    "Scanning AWS Route53 for S3 CNAMES which maybe vulnerable to takeover:"
  );
  const vuln_s3 = await missingS3Cname();
  //scans AWS Route53 for ElasticBeanstalk CNAMES vulnerable to takeover
  console.log(
    "Scanning AWS Route53 for elasticbeanstalk CNAMES which maybe vulnerable to takeover:"
  );
  const vuln_elasticbeanstalk = await missingElasticBeanStalkCname();
  //Printing Vulnerable Domains
  console.log("Vulnerable Domains", vulnerable_domains);
}

run();
