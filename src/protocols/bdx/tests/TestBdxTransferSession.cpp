#include <protocols/Protocols.h>
#include <protocols/bdx/BdxMessages.h>
#include <protocols/bdx/BdxTransferSession.h>

#include <string.h>

#include <nlunit-test.h>

#include <lib/core/TLV.h>
#include <lib/support/BufferReader.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/UnitTestRegistration.h>
#include <protocols/secure_channel/Constants.h>
#include <protocols/secure_channel/StatusReport.h>
#include <system/SystemPacketBuffer.h>

using namespace ::chip;
using namespace ::chip::bdx;
using namespace ::chip::Protocols;

namespace {

const TLV::Tag tlvStrTag  = TLV::ContextTag(4);
const TLV::Tag tlvListTag = TLV::ProfileTag(7777, 8888);
} // anonymous namespace

TransferSession::OutputEvent gInitiatorExpectedOutputEvent = TransferSession::OutputEventType::kNone;
TransferSession::OutputEvent gResponderExpectedOutputEvent = TransferSession::OutputEventType::kNone;

TransferSession * gReceiver = nullptr;
TransferSession * gSender   = nullptr;

// Arbitrary values for the test
uint16_t testSmallerBlockSize    = 64;
const uint16_t proposedBlockSize = 128;
uint32_t numBlocksSent           = 0;
uint32_t numBlockSends           = 10;
const uint64_t proposedOffset    = 64;
const uint64_t proposedLength    = 0;
const char metadataStr[11]       = { "hi_dad.txt" };

void SendAcceptTransferForInitReceived(nlTestSuite * inSuite);
void SendBlockForBlockQueryReceived(nlTestSuite * inSuite);
void SendPrematureBlockForBlockQueryReceived(nlTestSuite * inSuite);
void SendAndVerifyBlockAck(nlTestSuite * inSuite, TransferSession & ackReceiver, TransferSession & ackSender, bool expectEOF);
void SendAndVerifyQuery(nlTestSuite * inSuite, TransferSession & queryReceiver, TransferSession & querySender);

// Helper method for generating a complete TLV structure with a list containing a single tag and string
CHIP_ERROR WriteTLVString(uint8_t * buf, uint32_t bufLen, const char * data, uint32_t & written)
{
    written = 0;
    TLV::TLVWriter writer;
    writer.Init(buf, bufLen);

    {
        TLV::TLVWriter listWriter;
        ReturnErrorOnFailure(writer.OpenContainer(tlvListTag, TLV::kTLVType_List, listWriter));
        ReturnErrorOnFailure(listWriter.PutString(tlvStrTag, data));
        ReturnErrorOnFailure(writer.CloseContainer(listWriter));
    }

    ReturnErrorOnFailure(writer.Finalize());
    written = writer.GetLengthWritten();

    return CHIP_NO_ERROR;
}

// Helper method: read a TLV structure with a single tag and string and verify it matches expected string.
CHIP_ERROR ReadAndVerifyTLVString(const uint8_t * dataStart, uint32_t len, const char * expected, size_t expectedLen)
{
    TLV::TLVReader reader;
    char tmp[64]      = { 0 };
    size_t readLength = 0;
    VerifyOrReturnError(sizeof(tmp) > len, CHIP_ERROR_INTERNAL);

    reader.Init(dataStart, len);
    CHIP_ERROR err = reader.Next();

    VerifyOrReturnError(reader.GetTag() == tlvListTag, CHIP_ERROR_INTERNAL);

    // Metadata must have a top-level list
    {
        TLV::TLVReader listReader;
        ReturnErrorOnFailure(reader.OpenContainer(listReader));

        ReturnErrorOnFailure(listReader.Next());

        VerifyOrReturnError(listReader.GetTag() == tlvStrTag, CHIP_ERROR_INTERNAL);
        readLength = listReader.GetLength();
        VerifyOrReturnError(readLength == expectedLen, CHIP_ERROR_INTERNAL);
        ReturnErrorOnFailure(listReader.GetString(tmp, sizeof(tmp)));
        VerifyOrReturnError(!memcmp(expected, tmp, readLength), CHIP_ERROR_INTERNAL);

        ReturnErrorOnFailure(reader.CloseContainer(listReader));
    }

    return err;
}

CHIP_ERROR AttachHeaderAndSend(TransferSession::MessageTypeData typeData, chip::System::PacketBufferHandle msgBuf,
                               TransferSession & receiver)
{
    chip::PayloadHeader payloadHeader;
    payloadHeader.SetMessageType(typeData.ProtocolId, typeData.MessageType);

    ReturnErrorOnFailure(receiver.HandleMessageReceived(payloadHeader, std::move(msgBuf)));
    return CHIP_NO_ERROR;
}

// Helper method for verifying that a PacketBufferHandle contains a valid BDX header and message type matches expected.
void VerifyBdxMessageToSend(nlTestSuite * inSuite, const TransferSession::OutputEvent & outEvent)
{
    NL_TEST_ASSERT(inSuite, outEvent.EventType == TransferSession::OutputEventType::kMsgToSend);
    NL_TEST_ASSERT(inSuite, !outEvent.MsgData.IsNull());
    NL_TEST_ASSERT(inSuite, outEvent.msgTypeData.ProtocolId == Protocols::BDX::Id);
    NL_TEST_ASSERT(inSuite, outEvent.msgTypeData.MessageType == gInitiatorExpectedOutputEvent.msgTypeData.MessageType);
}

// Helper method for verifying that a PacketBufferHandle contains a valid StatusReport message and contains a specific StatusCode.
// The msg argument is expected to begin at the message data start, not at the PayloadHeader.
void VerifyStatusReport(nlTestSuite * inSuite, void * inContext, const System::PacketBufferHandle & msg, StatusCode expectedCode)
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    if (msg.IsNull())
    {
        NL_TEST_ASSERT(inSuite, false);
        return;
    }

    System::PacketBufferHandle msgCopy = msg.CloneData();
    if (msgCopy.IsNull())
    {
        NL_TEST_ASSERT(inSuite, false);
        return;
    }

    SecureChannel::StatusReport report;
    err = report.Parse(std::move(msgCopy));
    NL_TEST_ASSERT(inSuite, err == CHIP_NO_ERROR);
    NL_TEST_ASSERT(inSuite, report.GetGeneralCode() == SecureChannel::GeneralStatusCode::kFailure);
    NL_TEST_ASSERT(inSuite, report.GetProtocolId() == Protocols::BDX::Id);
    NL_TEST_ASSERT(inSuite, report.GetProtocolCode() == static_cast<uint16_t>(expectedCode));
}

void VerifyNoMoreOutput(nlTestSuite * inSuite, void * inContext, TransferSession & transferSession)
{
    TransferSession::OutputEvent event;
    NL_TEST_ASSERT(inSuite, event.EventType == TransferSession::OutputEventType::kNone);
}

void OnResponderOutputEventReceived(void * context, TransferSession::OutputEvent & event)
{
    ChipLogProgress(BDX, "OnResponderOutputEventReceived %s", event.ToString(event.EventType));
    nlTestSuite * inSuite = static_cast<nlTestSuite *>(context);
    if (inSuite == nullptr)
    {
        return;
    }

    switch (event.EventType)
    {
    case TransferSession::OutputEventType::kMsgToSend: {
        VerifyBdxMessageToSend(inSuite, event);
        CHIP_ERROR err = CHIP_NO_ERROR;
        // Pass Accept message to acceptReceiver
        err = AttachHeaderAndSend(event.msgTypeData, std::move(event.MsgData), *gSender);
        NL_TEST_ASSERT(inSuite, err == CHIP_NO_ERROR);
        break;
    }
    case TransferSession::OutputEventType::kInitReceived: {
        // Verify that all parsed TransferInit fields match what was sent by the initiator
        NL_TEST_ASSERT(inSuite, event.EventType == gResponderExpectedOutputEvent.EventType);
        NL_TEST_ASSERT(inSuite,
                       event.transferInitData.TransferCtlFlags == gResponderExpectedOutputEvent.transferInitData.TransferCtlFlags);
        NL_TEST_ASSERT(inSuite, event.transferInitData.MaxBlockSize == gResponderExpectedOutputEvent.transferInitData.MaxBlockSize);
        NL_TEST_ASSERT(inSuite, event.transferInitData.StartOffset == gResponderExpectedOutputEvent.transferInitData.StartOffset);
        NL_TEST_ASSERT(inSuite, event.transferInitData.Length == gResponderExpectedOutputEvent.transferInitData.Length);
        NL_TEST_ASSERT(inSuite, event.transferInitData.FileDesignator != nullptr);
        NL_TEST_ASSERT(inSuite,
                       event.transferInitData.FileDesLength == gResponderExpectedOutputEvent.transferInitData.FileDesLength);

        if (event.transferInitData.FileDesignator != nullptr)
        {
            NL_TEST_ASSERT(inSuite,
                           !memcmp(gResponderExpectedOutputEvent.transferInitData.FileDesignator,
                                   event.transferInitData.FileDesignator, event.transferInitData.FileDesLength));
        }
        if (event.transferInitData.Metadata != nullptr)
        {
            size_t metadataLength = gResponderExpectedOutputEvent.transferInitData.MetadataLength;
            NL_TEST_ASSERT(inSuite, event.transferInitData.MetadataLength == metadataLength);
            if (event.transferInitData.MetadataLength == metadataLength)
            {
                // Only check that metadata buffers match. The OutputEvent can still be inspected when this function returns to
                // parse the metadata and verify that it matches.
                NL_TEST_ASSERT(inSuite,
                               !memcmp(gResponderExpectedOutputEvent.transferInitData.Metadata, event.transferInitData.Metadata,
                                       event.transferInitData.MetadataLength));
            }
            else
            {
                NL_TEST_ASSERT(inSuite, false); // Metadata length mismatch
            }
        }

        // Send the ReceiveAccept msg and verify the metadata of the Accept message
        SendAcceptTransferForInitReceived(inSuite);
        break;
    }
    case TransferSession::OutputEventType::kQueryReceived:
        SendBlockForBlockQueryReceived(inSuite);
        break;
    case TransferSession::OutputEventType::kAckReceived:
        if (numBlocksSent < numBlockSends)
        {
            SendAndVerifyQuery(inSuite, *gReceiver, *gSender);
        }
        break;
    case TransferSession::OutputEventType::kNone:
    case TransferSession::OutputEventType::kAcceptReceived:
    case TransferSession::OutputEventType::kStatusReceived:
    case TransferSession::OutputEventType::kAckEOFReceived:
    case TransferSession::OutputEventType::kInternalError:
    case TransferSession::OutputEventType::kTransferTimeout:
    case TransferSession::OutputEventType::kQueryWithSkipReceived:
    case TransferSession::OutputEventType::kBlockReceived:
    default:
        break;
    }
}

void OnInitiatorOutputEventReceived(void * context, TransferSession::OutputEvent & event)
{
    ChipLogProgress(BDX, "OnInitiatorOutputEventReceived %s", event.ToString(event.EventType));
    nlTestSuite * inSuite = static_cast<nlTestSuite *>(context);
    if (inSuite == nullptr)
    {
        return;
    }

    switch (event.EventType)
    {
    case TransferSession::OutputEventType::kMsgToSend: {
        VerifyBdxMessageToSend(inSuite, event);
        CHIP_ERROR err = CHIP_NO_ERROR;
        err            = AttachHeaderAndSend(event.msgTypeData, std::move(event.MsgData), *gReceiver);
        NL_TEST_ASSERT(inSuite, err == CHIP_NO_ERROR);
        break;
    }
    case TransferSession::OutputEventType::kAckEOFReceived:
        gReceiver->Reset();
        gSender->Reset();
        break;
    case TransferSession::OutputEventType::kAcceptReceived: {
        // Verify received ReceiveAccept.
        // Client may want to inspect TransferControl, MaxBlockSize, StartOffset, Length, and Metadata, and may choose to reject the
        // Transfer at this point.
        NL_TEST_ASSERT(inSuite, event.EventType == TransferSession::OutputEventType::kAcceptReceived);
        NL_TEST_ASSERT(inSuite,
                       event.transferAcceptData.ControlMode == gResponderExpectedOutputEvent.transferAcceptData.ControlMode);
        NL_TEST_ASSERT(inSuite,
                       event.transferAcceptData.MaxBlockSize == gResponderExpectedOutputEvent.transferAcceptData.MaxBlockSize);
        NL_TEST_ASSERT(inSuite,
                       event.transferAcceptData.StartOffset == gResponderExpectedOutputEvent.transferAcceptData.StartOffset);
        NL_TEST_ASSERT(inSuite, event.transferAcceptData.Length == gResponderExpectedOutputEvent.transferAcceptData.Length);
        if (event.transferAcceptData.Metadata != nullptr)
        {
            size_t metadatalength = gResponderExpectedOutputEvent.transferAcceptData.MetadataLength;
            NL_TEST_ASSERT(inSuite, event.transferAcceptData.MetadataLength == metadatalength);
            if (event.transferAcceptData.MetadataLength == metadatalength)
            {
                // Only check that metadata buffers match. The OutputEvent can still be inspected when this function returns to
                // parse the metadata and verify that it matches.
                NL_TEST_ASSERT(inSuite,
                               !memcmp(gResponderExpectedOutputEvent.transferAcceptData.Metadata, event.transferAcceptData.Metadata,
                                       event.transferAcceptData.MetadataLength));
            }
            else
            {
                NL_TEST_ASSERT(inSuite, false); // Metadata length mismatch
            }
        }

        NL_TEST_ASSERT(inSuite, gSender != nullptr && gReceiver != nullptr);
        // Verify that MaxBlockSize was set appropriately
        NL_TEST_ASSERT(inSuite, gReceiver->GetTransferBlockSize() <= gResponderExpectedOutputEvent.transferInitData.MaxBlockSize);

        // Verify that MaxBlockSize was chosen correctly
        NL_TEST_ASSERT(inSuite, gSender->GetTransferBlockSize() == testSmallerBlockSize);
        NL_TEST_ASSERT(inSuite, gSender->GetTransferBlockSize() == gReceiver->GetTransferBlockSize());

        // Verify parsed TLV metadata matches the original
        CHIP_ERROR err =
            ReadAndVerifyTLVString(gResponderExpectedOutputEvent.transferAcceptData.Metadata,
                                   static_cast<uint32_t>(gResponderExpectedOutputEvent.transferAcceptData.MetadataLength),
                                   metadataStr, static_cast<uint16_t>(strlen(metadataStr)));
        NL_TEST_ASSERT(inSuite, err == CHIP_NO_ERROR);
        SendAndVerifyQuery(inSuite, *gReceiver, *gSender);
        break;
    }
    case TransferSession::OutputEventType::kBlockReceived: {
        NL_TEST_ASSERT(inSuite, event.blockdata.Data != nullptr);
        if (event.blockdata.Data != nullptr)
        {
            NL_TEST_ASSERT(inSuite,
                           !memcmp(gResponderExpectedOutputEvent.blockdata.Data, event.blockdata.Data, event.blockdata.Length));
            NL_TEST_ASSERT(inSuite, event.blockdata.BlockCounter == numBlocksSent);
        }

        // Test sending a premature block before block ack is recieved fails
        if (numBlocksSent == 0)
        {
            SendPrematureBlockForBlockQueryReceived(inSuite);
        }

        // Test Ack -> Query -> Block
        bool isEof = (numBlocksSent == numBlockSends - 1);
        numBlocksSent++;
        SendAndVerifyBlockAck(inSuite, *gReceiver, *gSender, isEof);
        break;
    }
    case TransferSession::OutputEventType::kInitReceived:
    case TransferSession::OutputEventType::kStatusReceived:
    case TransferSession::OutputEventType::kInternalError:
    case TransferSession::OutputEventType::kTransferTimeout:
    case TransferSession::OutputEventType::kQueryWithSkipReceived:
    case TransferSession::OutputEventType::kQueryReceived:
    case TransferSession::OutputEventType::kNone:
    case TransferSession::OutputEventType::kAckReceived:
    default:
        break;
    }
}

// Helper method for initializing two TransferSession objects, generating a TransferInit message, and passing it to a responding
// TransferSession.
void SendAndVerifyTransferInit(nlTestSuite * inSuite, TransferSession & initiator, TransferRole initiatorRole,
                               TransferSession::TransferInitData initData, TransferSession & responder,
                               BitFlags<TransferControlFlags> & responderControlOpts, uint16_t responderMaxBlock)
{
    TransferRole responderRole  = (initiatorRole == TransferRole::kSender) ? TransferRole::kReceiver : TransferRole::kSender;
    MessageType expectedInitMsg = (initiatorRole == TransferRole::kSender) ? MessageType::SendInit : MessageType::ReceiveInit;

    // Initializer responder to wait for transfer
    CHIP_ERROR err = responder.WaitForTransfer(responderRole, responderControlOpts, responderMaxBlock);
    NL_TEST_ASSERT(inSuite, err == CHIP_NO_ERROR);
    responder.RegisterOutputEventCallback(inSuite, OnResponderOutputEventReceived);

    initiator.RegisterOutputEventCallback(inSuite, OnInitiatorOutputEventReceived);

    // Set the expected output event when init message is sent to the initiator
    gInitiatorExpectedOutputEvent.EventType               = TransferSession::OutputEventType::kMsgToSend;
    gInitiatorExpectedOutputEvent.msgTypeData.ProtocolId  = Protocols::BDX::Id;
    gInitiatorExpectedOutputEvent.msgTypeData.MessageType = static_cast<uint8_t>(expectedInitMsg);

    // Set the expected BDX Init message to the responder
    gResponderExpectedOutputEvent.EventType        = TransferSession::OutputEventType::kInitReceived;
    gResponderExpectedOutputEvent.transferInitData = initData;

    // Verify initiator outputs respective Init message (depending on role) after StartTransfer()
    err = initiator.StartTransfer(initiatorRole, initData);
    NL_TEST_ASSERT(inSuite, err == CHIP_NO_ERROR);
}

// Helper method for initializing two TransferSession objects, generating a TransferInit message, and passing it to a responding
// TransferSession.
void SendAndVerifyTransferInitBadResponderRole(nlTestSuite * inSuite, TransferSession & initiator, TransferRole initiatorRole,
                                               TransferSession::TransferInitData initData, TransferSession & responder,
                                               BitFlags<TransferControlFlags> & responderControlOpts, uint16_t responderMaxBlock)
{
    TransferRole responderRole  = TransferRole::kReceiver;
    MessageType expectedInitMsg = (initiatorRole == TransferRole::kSender) ? MessageType::SendInit : MessageType::ReceiveInit;

    // Initializer responder to wait for transfer
    CHIP_ERROR err = responder.WaitForTransfer(responderRole, responderControlOpts, responderMaxBlock);
    NL_TEST_ASSERT(inSuite, err == CHIP_NO_ERROR);
    responder.RegisterOutputEventCallback(inSuite, OnResponderOutputEventReceived);

    initiator.RegisterOutputEventCallback(inSuite, OnInitiatorOutputEventReceived);

    // Set the expected output event when init message is sent to the initiator
    gInitiatorExpectedOutputEvent.EventType               = TransferSession::OutputEventType::kMsgToSend;
    gInitiatorExpectedOutputEvent.msgTypeData.ProtocolId  = Protocols::BDX::Id;
    gInitiatorExpectedOutputEvent.msgTypeData.MessageType = static_cast<uint8_t>(expectedInitMsg);

    // Set the expected BDX Init message to the responder
    gResponderExpectedOutputEvent.EventType        = TransferSession::OutputEventType::kInitReceived;
    gResponderExpectedOutputEvent.transferInitData = initData;

    // Verify initiator outputs respective Init message (depending on role) after StartTransfer()
    err = initiator.StartTransfer(initiatorRole, initData);
    NL_TEST_ASSERT(inSuite, err == CHIP_NO_ERROR);
}

// Helper method for sending an Accept message and verifying that the received parameters match what was sent.
// This function assumes that the acceptData struct contains transfer parameters that are valid responses to the original
// TransferInit message (for example, MaxBlockSize should be <= the TransferInit MaxBlockSize). If such parameters are invalid, the
// receiver should emit a StatusCode event instead.
//
// The acceptSender is the node that is sending the Accept message (not necessarily the same node that will send Blocks).
void SendAndVerifyAcceptMsg(nlTestSuite * inSuite, TransferSession & acceptSender, TransferRole acceptSenderRole,
                            TransferSession::TransferAcceptData acceptData, TransferSession & acceptReceiver,
                            TransferSession::TransferInitData initData)
{
    // acceptReceiver.RegisterOutputEventCallback(inSuite, OnResponderOutputEventReceived);

    // acceptSender.RegisterOutputEventCallback(inSuite, OnInitiatorOutputEventReceived);

    // If the node sending the Accept message is also the one that will send Blocks, then this should be a ReceiveAccept message.
    MessageType expectedMsg = (acceptSenderRole == TransferRole::kSender) ? MessageType::ReceiveAccept : MessageType::SendAccept;

    // Set the expected output event when init message is sent to the initiator
    gInitiatorExpectedOutputEvent.msgTypeData.MessageType = static_cast<uint8_t>(expectedMsg);

    // Set the expected BDX accept received message to the responder
    gResponderExpectedOutputEvent.EventType          = TransferSession::OutputEventType::kAcceptReceived;
    gResponderExpectedOutputEvent.transferAcceptData = acceptData;

    CHIP_ERROR err = acceptSender.AcceptTransfer(acceptData);
    NL_TEST_ASSERT(inSuite, err == CHIP_NO_ERROR);
}

// Helper method for preparing a sending a BlockQuery message between two TransferSession objects.
void SendAndVerifyQuery(nlTestSuite * inSuite, TransferSession & queryReceiver, TransferSession & querySender)
{
    // Set the expected output event message
    gInitiatorExpectedOutputEvent.msgTypeData.MessageType = static_cast<uint8_t>(MessageType::BlockQuery);

    gResponderExpectedOutputEvent.EventType = TransferSession::OutputEventType::kQueryReceived;
    // Verify that querySender emits BlockQuery message
    CHIP_ERROR err = querySender.PrepareBlockQuery();
    NL_TEST_ASSERT(inSuite, err == CHIP_NO_ERROR);
}

// Helper method for preparing a sending a Block message between two TransferSession objects. The sender refers to the node that is
// sending Blocks. Uses a static counter incremented with each call. Also verifies that block data received matches what was sent.
void SendAndVerifyArbitraryBlock(nlTestSuite * inSuite, TransferSession & sender, TransferSession & receiver, bool isEof,
                                 uint32_t inBlockCounter)
{
    CHIP_ERROR err           = CHIP_NO_ERROR;
    static uint8_t dataCount = 0;
    uint16_t maxBlockSize    = sender.GetTransferBlockSize();

    NL_TEST_ASSERT(inSuite, maxBlockSize > 0);
    System::PacketBufferHandle fakeDataBuf = System::PacketBufferHandle::New(maxBlockSize);
    if (fakeDataBuf.IsNull())
    {
        NL_TEST_ASSERT(inSuite, false);
        return;
    }

    uint8_t * fakeBlockData = fakeDataBuf->Start();
    fakeBlockData[0]        = dataCount++;

    TransferSession::BlockData blockData;
    blockData.Data   = fakeBlockData;
    blockData.Length = maxBlockSize;
    blockData.IsEof  = isEof;

    gInitiatorExpectedOutputEvent.msgTypeData.MessageType =
        static_cast<uint8_t>(isEof ? MessageType::BlockEOF : MessageType::Block);
    // Set the expected BDX accept received message to the responder
    gResponderExpectedOutputEvent.EventType = TransferSession::OutputEventType::kBlockReceived;
    gResponderExpectedOutputEvent.blockdata = blockData;

    // Provide Block data and verify sender emits Block message
    err = sender.PrepareBlock(blockData);
    NL_TEST_ASSERT(inSuite, err == CHIP_NO_ERROR);
}

// Helper method for sending a BlockAck or BlockAckEOF, depending on the state of the receiver.
void SendAndVerifyBlockAck(nlTestSuite * inSuite, TransferSession & ackReceiver, TransferSession & ackSender, bool expectEOF)
{

    gInitiatorExpectedOutputEvent.msgTypeData.MessageType =
        static_cast<uint8_t>(expectEOF ? MessageType::BlockAckEOF : MessageType::BlockAck);

    // Set the expected BDX accept received message to the responder
    gResponderExpectedOutputEvent.EventType =
        expectEOF ? TransferSession::OutputEventType::kAckEOFReceived : TransferSession::OutputEventType::kAckReceived;

    CHIP_ERROR err = ackSender.PrepareBlockAck();
    NL_TEST_ASSERT(inSuite, err == CHIP_NO_ERROR);
}

// Test a BDX transfer end to end. Tests BDX Init, Receive Accept, Block Query, Block and BlockEOF
void TestBDXTransferReceiverDrive(nlTestSuite * inSuite, void * inContext)
{
    TransferSession initiatingReceiver;
    TransferSession respondingSender;
    numBlocksSent = 0;

    // ReceiveInit parameters
    TransferSession::TransferInitData initOptions;
    initOptions.TransferCtlFlags = TransferControlFlags::kReceiverDrive;
    initOptions.MaxBlockSize     = proposedBlockSize;
    char testFileDes[9]          = { "test.txt" };
    initOptions.FileDesLength    = static_cast<uint16_t>(strlen(testFileDes));
    initOptions.FileDesignator   = reinterpret_cast<uint8_t *>(testFileDes);

    // Initialize respondingSender and pass ReceiveInit message
    // Initialize respondingReceiver
    BitFlags<TransferControlFlags> receiverOpts;
    receiverOpts.Set(initOptions.TransferCtlFlags);
    gSender   = &initiatingReceiver;
    gReceiver = &respondingSender;
    SendAndVerifyTransferInit(inSuite, initiatingReceiver, TransferRole::kReceiver, initOptions, respondingSender, receiverOpts,
                              proposedBlockSize);
}

// Test an accept transfer using a responding receiver and an initiating sender, receiver drive.
void SendAcceptTransferForInitReceived(nlTestSuite * inSuite)
{
    // Test metadata for Accept message
    uint8_t tlvBuf[64]    = { 0 };
    uint32_t bytesWritten = 0;
    CHIP_ERROR err        = WriteTLVString(tlvBuf, sizeof(tlvBuf), metadataStr, bytesWritten);
    NL_TEST_ASSERT(inSuite, err == CHIP_NO_ERROR);
    uint16_t metadataSize = static_cast<uint16_t>(bytesWritten & 0x0000FFFF);

    // Compose ReceiveAccept parameters struct and give to respondingSender
    TransferSession::TransferAcceptData acceptData;
    NL_TEST_ASSERT(inSuite, gSender != nullptr && gReceiver != nullptr);
    acceptData.ControlMode = gReceiver->GetControlMode();
    TransferRole role;

    if (gResponderExpectedOutputEvent.transferInitData.TransferCtlFlags == TransferControlFlags::kReceiverDrive)
    {
        acceptData.StartOffset    = proposedOffset;
        acceptData.Length         = proposedLength;
        acceptData.MaxBlockSize   = testSmallerBlockSize;
        acceptData.Metadata       = tlvBuf;
        acceptData.MetadataLength = metadataSize;
        role                      = TransferRole::kSender;
    }
    else
    {
        testSmallerBlockSize = 10;
        // Compose SendAccept parameters struct and give to respondingSender
        acceptData.MaxBlockSize   = testSmallerBlockSize;
        acceptData.StartOffset    = 0; // not used in SendAccept
        acceptData.Length         = 0; // not used in SendAccept
        acceptData.Metadata       = nullptr;
        acceptData.MetadataLength = 0;
        role                      = TransferRole::kReceiver;
    }

    SendAndVerifyAcceptMsg(inSuite, *gReceiver, role, acceptData, *gSender, gResponderExpectedOutputEvent.transferInitData);
}

// Test an accept transfer using a responding receiver and an initiating sender, receiver drive.
void SendBlockForBlockQueryReceived(nlTestSuite * inSuite)
{
    bool isEof = (numBlocksSent == numBlockSends - 1);
    SendAndVerifyArbitraryBlock(inSuite, *gReceiver, *gSender, isEof, numBlocksSent);
}

void SendPrematureBlockForBlockQueryReceived(nlTestSuite * inSuite)
{
    // Test only one block can be prepared at a time, without receiving a response to the first
    System::PacketBufferHandle fakeBuf = System::PacketBufferHandle::New(testSmallerBlockSize);
    TransferSession::BlockData prematureBlock;
    if (fakeBuf.IsNull())
    {
        NL_TEST_ASSERT(inSuite, false);
        return;
    }
    prematureBlock.Data   = fakeBuf->Start();
    prematureBlock.Length = testSmallerBlockSize;
    prematureBlock.IsEof  = false;

    gInitiatorExpectedOutputEvent.msgTypeData.MessageType =
        static_cast<uint8_t>(prematureBlock.IsEof ? MessageType::BlockEOF : MessageType::Block);

    // Set the expected BDX accept received message to the responder
    gResponderExpectedOutputEvent.EventType = TransferSession::OutputEventType::kBlockReceived;
    gResponderExpectedOutputEvent.blockdata = prematureBlock;

    CHIP_ERROR err = gReceiver->PrepareBlock(prematureBlock);
    NL_TEST_ASSERT(inSuite, err != CHIP_NO_ERROR);
}
// Test Suite

/**
 *  Test Suite that lists all the test functions.
 */
// clang-format off
static const nlTest sTests[] =
{
    NL_TEST_DEF("TestBDXTransferReceiverDrive", TestBDXTransferReceiverDrive),
    NL_TEST_SENTINEL()
};
// clang-format on

int TestBdxTransferSession_Setup(void * inContext)
{
    CHIP_ERROR error = chip::Platform::MemoryInit();
    if (error != CHIP_NO_ERROR)
        return FAILURE;
    return SUCCESS;
}

int TestBdxTransferSession_Teardown(void * inContext)
{
    chip::Platform::MemoryShutdown();
    return SUCCESS;
}

// clang-format off
static nlTestSuite sSuite =
{
    "Test-CHIP-TransferSession",
    &sTests[0],
    TestBdxTransferSession_Setup,
    TestBdxTransferSession_Teardown
};
// clang-format on

/**
 *  Main
 */
int TestBdxTransferSession()
{
    // Run test suit against one context
    nlTestRunner(&sSuite, nullptr);

    return (nlTestRunnerStats(&sSuite));
}

CHIP_REGISTER_TEST_SUITE(TestBdxTransferSession)
