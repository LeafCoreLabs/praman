// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CertificateRegistry {

    struct Certificate {
        string fileHash;
        string studentName;
        string rollNo;
        string course;
        string college;
        address issuer;
        uint256 issuedAt;
    }

    // Certificate storage
    mapping(string => Certificate) private certificates;
    mapping(string => bool) private certificateExists;

    // Authorized issuers (institutes)
    mapping(address => bool) public authorizedIssuers;

    address public owner;

    // Events
    event CertificateIssued(
        string certId,
        string fileHash,
        string studentName,
        string rollNo,
        string course,
        string college,
        address issuer,
        uint256 issuedAt
    );

    event IssuerAdded(address indexed issuer);
    event IssuerRemoved(address indexed issuer);

    // -------------------- Modifiers --------------------
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }

    modifier onlyAuthorized() {
        require(authorizedIssuers[msg.sender], "Not an authorized issuer");
        _;
    }

    // -------------------- Constructor --------------------
    constructor() {
        owner = msg.sender;
        authorizedIssuers[owner] = true; // Owner can issue certificates
    }

    // -------------------- Owner Functions --------------------
    function addAuthorizedIssuer(address _issuer) public onlyOwner {
        authorizedIssuers[_issuer] = true;
        emit IssuerAdded(_issuer);
    }

    function removeAuthorizedIssuer(address _issuer) public onlyOwner {
        authorizedIssuers[_issuer] = false;
        emit IssuerRemoved(_issuer);
    }

    // -------------------- Certificate Functions --------------------
    function issueCertificate(
        string memory certId,
        string memory fileHash,
        string memory studentName,
        string memory rollNo,
        string memory course,
        string memory college
    ) public onlyAuthorized {
        require(!certificateExists[certId], "Certificate already exists");
        require(bytes(certId).length > 0, "Certificate ID cannot be empty");
        require(bytes(fileHash).length > 0, "File hash cannot be empty");

        certificates[certId] = Certificate(
            fileHash,
            studentName,
            rollNo,
            course,
            college,
            msg.sender,
            block.timestamp
        );
        certificateExists[certId] = true;

        emit CertificateIssued(certId, fileHash, studentName, rollNo, course, college, msg.sender, block.timestamp);
    }

    function verifyCertificate(string memory certId) public view returns (
        string memory fileHash,
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
            cert.fileHash,
            cert.studentName,
            cert.rollNo,
            cert.course,
            cert.college,
            cert.issuer,
            cert.issuedAt
        );
    }

    function isAuthorized(address _issuer) public view returns (bool) {
        return authorizedIssuers[_issuer];
    }
}
