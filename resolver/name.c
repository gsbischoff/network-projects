#include <WinSock2.h>
#include <windows.h>
#include <stdio.h>

#include "dns.h"

// gcc -std=c99 name.c -o t -lws2_32

void
SerializeDNSHeader(struct dns_message_header *Header)
{
	// Change header fields to network byte order
	Header->Identifier    = htons(Header->Identifier);
	Header->Flags         = htons(Header->Flags);
	Header->NumQuestions  = htons(Header->NumQuestions);
	Header->NumAnswerRRs  = htons(Header->NumAnswerRRs);
	Header->NumAuthRRs    = htons(Header->NumAuthRRs);
	Header->NumAdditional = htons(Header->NumAdditional);
}

void
DeserializeDNSHeader(struct dns_message_header *Header)
{
	// Change header fields to host byte order
	Header->Identifier    = ntohs(Header->Identifier);
	Header->Flags         = ntohs(Header->Flags);
	Header->NumQuestions  = ntohs(Header->NumQuestions);
	Header->NumAnswerRRs  = ntohs(Header->NumAnswerRRs);
	Header->NumAuthRRs    = ntohs(Header->NumAuthRRs);
	Header->NumAdditional = ntohs(Header->NumAdditional);
}

void
PrintDNSHeader(struct dns_message_header *ResponseHeader)
{
	printf("\nIdentifier    %x\n"
			"Flags:  %x\n"
			"\tQR      %x\n"
			"\tOpcode  %x\n"	/* Kind of query */
			"\tAA      %x\n"	/* Authoritative Answer */
			"\tTC      %x\n"	/* TrunCation */
			"\tRD      %x\n"	/* Recursion Desired */
			"\tRA      %x\n"	/* Recursion Available */
			"\tZ       %x\n"	/* --- Reserved --- */
			"\tRCODE   %x\n"	/* Response code */
			"NumQuestions   %u\n"
			"NumAnswerRRs   %u\n"
			"NumAuthRRs     %u\n"
			"NumAdditional  %u\n", 
			ResponseHeader->Identifier, 
			ResponseHeader->Flags,
				ResponseHeader->QR,
				ResponseHeader->OPCODE, //Opcode,
				ResponseHeader->AA, //AA,
				ResponseHeader->TC, //TC,
				ResponseHeader->RD, //RD,
				ResponseHeader->RA, //RA,
				ResponseHeader->Z,  //Z,
				ResponseHeader->RCODE, //RCODE,
			ResponseHeader->NumQuestions, ResponseHeader->NumAnswerRRs,
			ResponseHeader->NumAuthRRs, ResponseHeader->NumAdditional);
}

void *
ParseQuestions(void *QuestionStart, short NumQuestions)
{
	unsigned char *MemoryPtr = QuestionStart;
	for(int QuestionIndex = 0;
		QuestionIndex < NumQuestions;
		++QuestionIndex)
	{
		while(MemoryPtr[0])
		{
			
		}
	}
}

void *
ParseAnswerRRs(void *QuestionStart, short NumQuestions);

void *
ParseAuthRRs(void *QuestionStart, short NumQuestions);

void *
ParseAdditional(void *QuestionStart, short NumQuestions);

void
ParseDNSMessage(char *Response, int ResponseLength)
{
	struct dns_message_header *Header = Response;
	DeserializeDNSHeader(Header);

	void *ResponsePtr = Response + sizeof(struct dns_message_header);

	ResponsePtr = ParseQuestions(ResponsePtr, Header->NumQuestions);
	ResponsePtr = ParseAnswerRRs(ResponsePtr, Header->NumAnswerRRs);
	ResponsePtr = ParseAuthRRs(ResponsePtr, Header->NumAuthRRs);
	ResponsePtr = ParseAdditional(ResponsePtr, Header->NumAdditional);

	short QTYPE, QCLASS;
}

struct dns_message
FormatDNSMessage(struct dns_message_header Header,
				 struct dns_question *Questions)
{
	char *Message, *MsgPtr;

	// Serialize header -- change to network-order!
	SerializeDNSHeader(&Header);

	// Make space for header, questions
	int Length = sizeof(struct dns_message_header);
	
	for(struct dns_question *QuestionPtr = Questions;
		QuestionPtr; QuestionPtr = QuestionPtr->Next)
	{
		Length += QuestionPtr->QLEN + 2*sizeof(short);
	}

	Message = malloc(Length);

	// Fill that space
	memcpy(Message, &Header, sizeof(struct dns_message_header));
	MsgPtr = Message + sizeof(struct dns_message_header);

	for(struct dns_question *QuestionPtr = Questions;
		QuestionPtr; QuestionPtr = QuestionPtr->Next)
	{
		memcpy(MsgPtr, QuestionPtr->QNAME, QuestionPtr->QLEN);
		MsgPtr += QuestionPtr->QLEN;

		((short *)MsgPtr)[0] = htons(QuestionPtr->QTYPE);
		((short *)MsgPtr)[1] = htons(QuestionPtr->QCLASS);
		MsgPtr += 2*sizeof(short);
	}

	struct dns_message Result;
	Result.Length = Length;
	Result.Message = Message;

	return Result;
}

char *
ConvertToMessageForm(char *HostSource)
{
	int len = strlen(HostSource);
	char *Result = malloc(len + 2);

	if(len == 0)
		return 0;

	Result[0] = '.';
	for(int Index = 0;
		Index < len + 1;
		++Index)
		Result[Index + 1] = HostSource[Index];

	int LabelIndex = 0;
	for(char *ptr = Result;
		*ptr; ptr += LabelIndex + 1)
	{
		for(LabelIndex = 0;
			ptr[LabelIndex + 1] != '.' && ptr[LabelIndex + 1];
			++LabelIndex);
		
		*ptr = LabelIndex;
	}

	return Result;
}


int
main(int argc, char **argv)
{
	int ClientSocket;
	char *DomainName = 0;
	unsigned long ServerHost = 0;

	if(argc >= 3 && (argc % 2) == 1)
	{
		for(int Index = 1; Index < argc - 1; ++Index)
		{
			if(argv[Index][0] == '-')
			{
				switch(argv[Index][1])
				{
					case 'h':
						DomainName = argv[Index + 1];
						break;
					case 's':
						ServerHost = inet_addr(argv[Index + 1]);
						break;
					default:
						break;
				}
			}
		}
	}
	if(!ServerHost)
		ServerHost = inet_addr("8.8.8.8");

	if(!DomainName)
		exit(1);


	struct sockaddr_in ServerAddr;

	memset(&ServerAddr, 0, sizeof(ServerAddr));
	ServerAddr.sin_family		= AF_INET;
	ServerAddr.sin_addr.s_addr	= ServerHost;
	ServerAddr.sin_port			= htons(53);

	WSADATA WSAData = {0};
	WSAStartup(MAKEWORD(1,1), &WSAData);

	if((ClientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		exit(1);

	// Format our question
	
	// NOTE: Our machine is *little-endian*, we must swap these values into network order when assigning them
	//       But we're smart network programmers, we were totally going to do that already

	// Header
	struct dns_message_header Header = {0};
	Header.Identifier = 0xABCD;
	Header.RD = 1;
	Header.NumQuestions = 1;

	// Create a question
	struct dns_question Question = {0};

	Question.QNAME  = ConvertToMessageForm(DomainName);
	Question.QLEN   = strlen(Question.QNAME) + 1;
	Question.QTYPE  = 1;
	Question.QCLASS = 1;

	char *QNBuffer = Question.QNAME;

	// Format entire message; Header, then questions
	// and *change the byte order to network-order*!
	struct dns_message Message = FormatDNSMessage(Header, &Question);	// Header, then LLs to fields

/*	Reference message bytes of query for google.com
	unsigned char boof[] = {0xAA,0xfA,0x1,0,0,1,0,0,0,0,0,0, 
							6,'g','o','o','g','l','e', 3 ,'c','o','m','\0', //'','','','','',
							0,1, 
							0,1};
*/

	sendto(ClientSocket, Message.Message, Message.Length, 0, (struct sockaddr *) 
		   &ServerAddr, sizeof(ServerAddr));

	free(QNBuffer);
	free(Message.Message);

	char RecvBuffer[512]; 	/* RFC 1035 p.10: "UDP messages    512 octets or less" */
	//struct DNSMessageHeader RecvBuffer;
	//unsigned char RecvBuffer[512] = {0};
	struct sockaddr_in FromAddr;
	int FromLen = sizeof(FromAddr);

	int BytesRecv = recvfrom(ClientSocket, RecvBuffer, 512, 0, (struct sockaddr *)
							 &FromAddr, &FromLen);
	
	printf("BytesRecv: %u\nAddr: %s\n", BytesRecv, inet_ntoa(FromAddr.sin_addr));

	if(BytesRecv < sizeof(struct dns_message_header))
	{
		printf("Error! Recieved %u bytes!\n", BytesRecv);
		closesocket(ClientSocket);
		WSACleanup();
		exit(1);
	}
	int ResponseLength = BytesRecv;
	char *Response = RecvBuffer;

	ParseDNSMessage(Response, ResponseLength);







	struct dns_message_header *ResponseHeader;
	ResponseHeader = (struct dns_message_header *) &RecvBuffer;
	PrintDNSHeader(ResponseHeader);

	
#if 0
	
	printf("Buffer contents: ");
	for(int i = 0; i < 12; ++i)
		printf("%02x", RBptr[i]);

#endif
	closesocket(ClientSocket);
	WSACleanup();
	return(0);
}