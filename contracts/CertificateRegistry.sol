// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CertificateRegistry {

    struct Certificate {
        string certId;
        string metadataHash;
        string studentName;
        string rollNo;
        string course;
        string college;
        address issuer;
        uint256 issuedAt;
    }

    mapping(string => Certificate) private certificates;
    mapping(string => bool) private certificateExists;
    mapping(address => bool) public authorizedIssuers;
    mapping(string => string) private metadataToCertId;

    address public owner;

    event CertificateIssued(
        string certId,
        string metadataHash,
        string studentName,
        string rollNo,
        string course,
        string college,
        address issuer,
        uint256 issuedAt
    );

    event IssuerAdded(address indexed issuer);
    event IssuerRemoved(address indexed issuer);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }

    modifier onlyAuthorized() {
        require(authorizedIssuers[msg.sender], "Not an authorized issuer");
        _;
    }

    constructor() {
        owner = msg.sender;
        authorizedIssuers[owner] = true;
    }

    function addAuthorizedIssuer(address _issuer) public onlyOwner {
        authorizedIssuers[_issuer] = true;
        emit IssuerAdded(_issuer);
    }

    function removeAuthorizedIssuer(address _issuer) public onlyOwner {
        authorizedIssuers[_issuer] = false;
        emit IssuerRemoved(_issuer);
    }

    function issueCertificate(
        string memory certId,
        string memory metadataHash,
        string memory studentName,
        string memory rollNo,
        string memory course,
        string memory college
    ) public onlyAuthorized {
        require(!certificateExists[certId], "Certificate already exists");
        require(bytes(certId).length > 0, "Certificate ID cannot be empty");
        require(bytes(metadataHash).length > 0, "Metadata hash cannot be empty");

        certificates[certId] = Certificate(
            certId,
            metadataHash,
            studentName,
            rollNo,
            course,
            college,
            msg.sender,
            block.timestamp
        );
        certificateExists[certId] = true;
        metadataToCertId[metadataHash] = certId;

        emit CertificateIssued(certId, metadataHash, studentName, rollNo, course, college, msg.sender, block.timestamp);
    }

    function verifyCertificate(string memory certId) public view returns (
        string memory metadataHash,
        string memory studentName,
        string memory rollNo,
        string memory course,
        string memory college,
        address issuer,
        uint256 issuedAt
    ) {
        require(certificateExists[certId], "Certificate not found");
        Certificate memory cert = certificates[certId];
        return (
            cert.metadataHash,
            cert.studentName,
            cert.rollNo,
            cert.course,
            cert.college,
            cert.issuer,
            cert.issuedAt
        );
    }

    function verifyMetadataHash(string memory metadataHash) public view returns (bool exists, string memory certId) {
        certId = metadataToCertId[metadataHash];
        exists = bytes(certId).length > 0;
    }

    function isAuthorized(address _issuer) public view returns (bool) {
        return authorizedIssuers[_issuer];
    }
}
