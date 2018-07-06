#include <WinSock2.h>
#include <windows.h>
#include <stdio.h>

#include "dns.h"

// gcc -std=c99 name.c -o t -lws2_32

struct dns_message
FormatDNSMessage(struct dns_message_header Header,
				 struct dns_question *Questions)
{
	char *Message, *MsgPtr;

	// Serialize header -- change to network-order!
	Header.Identifier    = htons(Header.Identifier);
	Header.Flags         = htons(Header.Flags);
	Header.NumQuestions  = htons(Header.NumQuestions);
	Header.NumAnswerRRs  = htons(Header.NumAnswerRRs);
	Header.NumAuthRRs    = htons(Header.NumAuthRRs);
	Header.NumAdditional = htons(Header.NumAdditional);

	// Make space for header, questions. then call memcpy
	int Length = sizeof(struct dns_message_header);
	
	for(struct dns_question *QuestionPtr = Questions;
		QuestionPtr; QuestionPtr = QuestionPtr->Next)
	{
		Length += QuestionPtr->QLEN + 2*sizeof(short);
	}

	Message = malloc(Length);
	MsgPtr = Message + sizeof(struct dns_message_header);

	memcpy(Message, &Header, sizeof(struct dns_message_header));

	for(struct dns_question *QuestionPtr = Questions;
		QuestionPtr; QuestionPtr = QuestionPtr->Next)
	{
		memcpy(MsgPtr, QuestionPtr->QNAME, QuestionPtr->QLEN);
		MsgPtr += QuestionPtr->QLEN + 2*sizeof(short);
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
#if 1
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

	Question.QNAME = ConvertToMessageForm(DomainName);
	Question.QLEN = strlen(Question.QNAME);
	Question.QTYPE = 1;
	Question.QCLASS = 1;

	char *QNBuffer = Question.QNAME;

	// Format entire message; Header, then questions
	// and *change the byte order to network-order*!
	struct dns_message Message = FormatDNSMessage(Header, &Question);	// Header, then LLs to fields
	

/*
	unsigned char boof[] = {0xAA,0xfA,0x1,0,0,1,0,0,0,0,0,0, 
							6,'g','o','o','g','l','e', 3 ,'c','o','m','\0', //'','','','','',
							0,1, 
							0,1};
*/

	sendto(ClientSocket, &Message, Message.Length, 0, (struct sockaddr *) 
		   &ServerAddr, sizeof(ServerAddr));

	free(QNBuffer);
	free(Message.Message);

	//char RecvBuffer[512]; 	/* RFC 1035 p.10: "UDP messages    512 octets or less" */
	//struct DNSMessageHeader RecvBuffer;
	unsigned char RecvBuffer[512] = {0};
	struct sockaddr_in FromAddr;
	int FromLen = sizeof(FromAddr);

	int BytesRecv = recvfrom(ClientSocket, (char *) RecvBuffer, 512, 0, (struct sockaddr *)
							 &FromAddr, &FromLen);
	
	printf("BytesRecv: %u\nAddr: %s\n", BytesRecv, inet_ntoa(FromAddr.sin_addr));

	if(BytesRecv < sizeof(struct DNSMessageHeader))
	{
		printf("Error! Recieved %u bytes!\n", BytesRecv);
		closesocket(ClientSocket);
		WSACleanup();
		exit(1);
	}

	unsigned char *RBptr = (unsigned char *)&RecvBuffer;
	printf("INITBuffer cont: ");
	for(int i = 0; i < 12; ++i)
		printf("%02x", RBptr[i]);
	struct DNSMessageHeader *Recv = (struct DNSMessageHeader *) RecvBuffer;
	Recv->Identifier    = ntohs(Recv->Identifier);
	Recv->Flags         = ntohs(Recv->Flags);
	Recv->NumQuestions  = ntohs(Recv->NumQuestions);
	Recv->NumAnswerRRs  = ntohs(Recv->NumAnswerRRs);
	Recv->NumAuthRRs    = ntohs(Recv->NumAuthRRs);
	Recv->NumAdditional = ntohs(Recv->NumAdditional);
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
			Recv->Identifier, 
			Recv->Flags,
				(Recv->Flags >> 15) & 1,
				(Recv->Flags >> 11) & 0xF, //Opcode,
				(Recv->Flags >> 10) & 1, //AA,
				(Recv->Flags >>  9) & 1, //TC,
				(Recv->Flags >>  8) & 1, //RD,
				(Recv->Flags >>  7) & 1, //RA,
				(Recv->Flags >>  4) & 7, //Z,
				(Recv->Flags >>  0) & 0xF, //RCODE,
			Recv->NumQuestions, Recv->NumAnswerRRs,
			Recv->NumAuthRRs, Recv->NumAdditional);
	
	printf("Buffer contents: ");
	for(int i = 0; i < 12; ++i)
		printf("%02x", RBptr[i]);

	closesocket(ClientSocket);
	WSACleanup();
#endif
	return(0);
}