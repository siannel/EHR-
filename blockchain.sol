// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract HealthcareABAC {
    struct Record {
        bytes32 dataHash;  // Hash of the actual medical record data
        string timestamp;
    }

    struct User {
        string hospital;
        string department;
        string position;
        bool isLoggedIn;
    }

    address public admin;
    mapping(address => User) public users;
    mapping(address => bool) public patients;
    mapping(address => Record[]) private records;
    mapping(address => bytes32) public patientKeys;  // Patient's secret key for direct access

    modifier onlyAdmin() {
        require(msg.sender == admin, "Access denied: Only admin can perform this action");
        _;
    }

    modifier onlyLoggedIn() {
        require(users[msg.sender].isLoggedIn, "User not logged in");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerPatient(address _patient, string memory _hospital, bytes32 _key) public onlyAdmin {
        patients[_patient] = true;
        users[_patient] = User(_hospital, "", "", false);
        patientKeys[_patient] = _key;
    }

    function registerDoctor(
        address _doctor,
        string memory _hospital,
        string memory _department,
        string memory _position
    ) public onlyAdmin {
        users[_doctor] = User(_hospital, _department, _position, false);
    }

    function registerThirdParty(
        address _thirdParty,
        string memory _hospital,
        string memory _department,
        string memory _position
    ) public onlyAdmin {
        users[_thirdParty] = User(_hospital, _department, _position, false);
    }

    function setMedicalRecord(
        address _patient,
        bytes32 _dataHash,
        string memory _timestamp
    ) public onlyAdmin {
        require(patients[_patient], "Patient not registered");
        records[_patient].push(Record(_dataHash, _timestamp));
    }

    function login() public {
        require(bytes(users[msg.sender].position).length > 0, "User not registered");
        users[msg.sender].isLoggedIn = true;
    }

    function logout() public {
        require(users[msg.sender].isLoggedIn, "User not logged in");
        users[msg.sender].isLoggedIn = false;
    }

    function getMedicalRecord(address _patient, bytes32 _key) public view onlyLoggedIn returns (bytes32) {
        require(patients[_patient], "Patient not registered");

        if (_key != 0 && _key == patientKeys[_patient]) {
            return records[_patient][records[_patient].length - 1].dataHash;
        } else if (matchesAttributes(msg.sender, _patient)) {
            return records[_patient][records[_patient].length - 1].dataHash;
        }

        revert("Access denied: Unauthorized");
    }

    function searchMedicalRecords(
        address _patient,
        bytes32 searchToken,
        bytes32 pp
    ) public view onlyLoggedIn returns (bytes32[] memory) {
        require(patients[_patient], "Patient not registered");
        require(matchesAttributes(msg.sender, _patient), "Access denied: Unauthorized");

        bytes32[] memory results = new bytes32[](records[_patient].length);
        uint256 resultCount = 0;

        for (uint256 i = 0; i < records[_patient].length; i++) {
            if (complexMatchesSearchToken(records[_patient][i].dataHash, searchToken, pp)) {
                results[resultCount] = records[_patient][i].dataHash;
                resultCount++;
            }
        }

        // Trim the results array to the actual number of results
        bytes32[] memory trimmedResults = new bytes32[](resultCount);
        for (uint256 i = 0; i < resultCount; i++) {
            trimmedResults[i] = results[i];
        }

        return trimmedResults;
    }

    function matchesAttributes(address _user, address _patient) internal view returns (bool) {
        return keccak256(abi.encodePacked(users[_user].hospital)) == keccak256(abi.encodePacked(users[_patient].hospital));
    }

    function complexMatchesSearchToken(bytes32 dataHash, bytes32 searchToken, bytes32 pp) internal pure returns (bool) {
        // Example complex search: check if the search token, modified by pp, is a substring of the data hash
        bytes memory combined = abi.encodePacked(searchToken, pp);
        bytes32 combinedHash = keccak256(combined);

        // Here we consider it a match if combinedHash is a part of the dataHash
        return dataHash == combinedHash; // In a real scenario, use more complex logic
    }
}
