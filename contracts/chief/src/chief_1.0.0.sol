pragma solidity ^0.5.3;

/* for remix
import "github.com/SmartMeshFoundation/Spectrum/contracts/chief/src/chief_abs_0.5.sol"; // for remix
import "github.com/SmartMeshFoundation/Spectrum/contracts/chief/src/chief_base_0.5_v0.0.1.sol"; // for remix
*/

/* local */
import "./chief_abs_0.5.sol";
import "./chief_base_0.5_v0.0.1.sol";

contract TribeChief_1_0_0 is Chief {

    string vsn = "1.0.0";

    struct BlackMember {
        address addr;
        uint score;
        uint number;
    }

    ChiefBase private base;

    address[] public _blackList;
    address[] public _blackMembers;
    address[] public _signerList;
    address[] public _volunteerList;
    uint public blockNumber;

    // the mapping of the signer score and the block number
    mapping(address => uint) public signersMap;
    mapping(address => uint) public volunteerMap;

    // the mapping of the blacklist and block number
    mapping(address => BlackMember) public blMap;

    function getLeader() public view returns (address[] memory) {
        return base.getLeaderList();
    }

    constructor(address baseAddress, address pocAddress) public {
        base = ChiefBase(baseAddress);
        base.init(pocAddress, address(this));

        address[] memory leaderList = base.getLeaderList();
        require(leaderList.length > 0);

        signersMap[leaderList[0]] = 1;
        _signerList.push(leaderList[0]);

        for (uint i = _signerList.length; i < base.getSignerLimit(); i++) {
            // placeholder
            _signerList.push(address(0));
        }

    }

    modifier allow() {
        address _addr = msg.sender;
        require(uint160(_addr) != uint160(0));
        require(signersMap[_addr] > 0 || base.isLeader(_addr));
        _;
    }

    function pushVolunteer(address addr) public {
        /*
        if ( _signerList.length < base.getSignerLimit() ) {
            _signerList.push(addr);
            signersMap[addr] = 1;
        }
        */
        if (_volunteerList.length < base.getVolunteerLimit()) {
            _volunteerList.push(addr);
            volunteerMap[addr] = 1;
        }
    }

    function pushBlackMember(address addr) public payable {
        BlackMember memory bm = BlackMember(addr, 1, block.number);
        if (blMap[addr].score != 0) {
            if (blMap[addr].score < 3) {
                blMap[addr].score += 1;
                blMap[addr].number = block.number;
                if (blMap[addr].score == 3) {
                    _blackList.push(addr);
                }
            }
        } else {
            blMap[addr] = bm;
            _blackMembers.push(addr);
        }
    }

    // every signer call this func before update
    function removeBlackMember(address addr) public payable {
        if (blMap[addr].score > 0) {
            if (blMap[addr].score >= 3) {
                for (uint i = 0; i < _blackList.length; i++) {
                    if (_blackList[i] == addr) {
                        if (_blackList.length > 1) {
                            for (uint j = i; j < _blackList.length - 1; j++) {
                                _blackList[j] = _blackList[j + 1];
                            }
                            i--;
                        }
                        _blackList.length -= 1;
                    }
                }
            }
            delete blMap[addr];
            for (uint i = 0; i < _blackMembers.length; i++) {
                if (_blackMembers[i] == addr) {
                    if (_blackMembers.length > 1) {
                        for (uint j = i; j < _blackMembers.length - 1; j++) {
                            _blackMembers[j] = _blackMembers[j + 1];
                        }
                        i--;
                    }
                    _blackMembers.length -= 1;
                }
            }
        }
    }

    // append a signer
    function pushSigner(address signer, uint idx) private {
        if (_signerList.length < base.getSignerLimit()) {
            if (idx < base.getSignerLimit()) {
                delete signersMap[_signerList[idx]];
                _signerList[idx] = signer;
            } else {
                _signerList.push(signer);
            }
            signersMap[signer] = 1;
        }
    }
    // delete a signer by index
    function deleteSigner(uint index) private {
        uint slen = _signerList.length;
        if (index < slen) {
            delete signersMap[_signerList[index]];
            for (uint i = index; i < slen - 1; i++) {
                _signerList[i] = _signerList[i + 1];
            }
            _signerList.length -= 1;
        }
    }

    // delete a volunteer by index
    function deleteVolunteer(uint index) private {
        uint vlen = _volunteerList.length;
        if (index < vlen) {
            delete volunteerMap[_volunteerList[index]];
            for (uint i = index; i < vlen - 1; i++) {
                _volunteerList[i] = _volunteerList[i + 1];
            }
            _volunteerList.length -= 1;
        }
    }

    // clean all of list without idx 0, 0 is leader
    function genSigners_clean_all_signer() public {
        // clean all of signerList
        address[] memory sl = new address[](_signerList.length);
        for (uint j = 0; j < sl.length; j++) {
            sl[j] = _signerList[j];
        }
        // do clean
        for (uint i0 = sl.length; i0 > 1; i0--) {
            uint sIndex = i0 - 1;
            deleteSigner(sIndex);

            address signerI = sl[sIndex];
            if (sIndex > 0 && uint160(signerI) != uint160(0)) {
                //TODO move sl[sIndex] to POC volunteerList and weight-1 ;

            }
        }
    }

    function genSigners_set_leader() public {
        address g = _signerList[0];
        address[] memory leaders = base.getLeaderList();
        for (uint i = 0; i < leaders.length; i++) {
            address l = leaders[i];
            if (g == l) {
                if (i == leaders.length - 1) {
                    pushSigner(leaders[0], 0);
                } else {
                    pushSigner(leaders[i + 1], 0);
                }
            }
        }
    }

    // push volunteerList to signerList
    function genSigners_v2s() public {
        for (uint i1 = 0; i1 < _volunteerList.length; i1++) {
            address v = _volunteerList[i1];
            pushSigner(v, base.getSignerLimit() + 1);
        }
        for (uint i2 = _signerList.length; i2 < base.getSignerLimit(); i2++) {
            // placeholder
            _signerList.push(address(0));
        }
    }

    // clean volunteerList
    function genSigners_clean_volunteer() public {
        for (uint i2 = _volunteerList.length; i2 > 0; i2--) {
            uint vIndex = i2 - 1;
            deleteVolunteer(vIndex);
        }
    }

    function genSigners() public {
        genSigners_clean_all_signer();
        // generate
        genSigners_set_leader();
        // push volunteerList to signerList
        genSigners_v2s();
        // clean volunteerList
        genSigners_clean_volunteer();
    }

    function update(address volunteer) public allow() {

        blockNumber = block.number;
        removeBlackMember(msg.sender);

        uint l = _signerList.length;
        uint signerIdx = uint(blockNumber % l);
        address si = _signerList[signerIdx];

        //1 : not leader signer, and `sender!=si` move `si` to waitList in POC contract
        if (signerIdx > uint(0)) {

            if (uint160(volunteer) != uint160(0)) {
                pushVolunteer(volunteer);
            }

            if (si != address(0) && msg.sender != si) {
                // move si to stopList in POC contract
                if (base.pocAddStop(si) == - 1) {
                    // TODO move to meshbox stopList
                    // TODO move to meshbox stopList
                    // TODO move to meshbox stopList
                }

                delete signersMap[si];
                // mark 0
                _signerList[signerIdx] = address(0);
            }
        }

        //2 : last block, reset signerList
        if (l == base.getSignerLimit() && signerIdx == uint(base.getSignerLimit() - 1)) {
            genSigners();
        }

    }

    function getStatus() public view returns (
    //address[] volunteerList,
        address[] memory signerList,
        address[] memory blackList, // vsn 0.0.3
        uint[] memory scoreList,
        uint[] memory numberList,
        uint totalVolunteer,
        uint number
    ) {
        scoreList = new uint[](_signerList.length);
        numberList = new uint[](_signerList.length);
        for (uint i = 0; i < _signerList.length; i ++) {
            scoreList[i] = 0;
            numberList[i] = signersMap[_signerList[i]];
        }
        // TODO
        blackList = _blackList;

        signerList = _signerList;
        // vsn 0.0.3
        number = blockNumber;
        totalVolunteer = _volunteerList.length;
    }

    function version() public view returns (string memory) {return vsn;}

    function getSignerLimit() public view returns (uint) {return base.getSignerLimit();}

    function getEpoch() public view returns (uint) {return base.getEpoch();}

    function getVolunteerLimit() public view returns (uint) {return base.getVolunteerLimit();}

    function getVolunteers() public view returns (
        address[] memory volunteerList,
        uint[] memory weightList,
        uint length
    ){
        weightList = new uint[](_volunteerList.length);
        volunteerList = _volunteerList;
        length = volunteerList.length;
    }

    // TODO
    function filterVolunteer(address[] memory volunteers) public view returns (uint[] memory result) {}
}
