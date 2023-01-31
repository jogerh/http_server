#include "http_server.h"

int main(int argc, char* argv[])
{
	const auto url = L"http://+:9002/";
	char* wwwAuthVal = nullptr;

	if (argc > 1)
	{
		printf("Mutual auth header will be overridden to: %s\n", argv[1]);
		wwwAuthVal = argv[1];
	}

	HttpApi api;

	auto session = api.CreateSession();
	session.EnableAuthNegotiation();

	const auto queue = api.CreateRequestQueue(L"MyQueue");

	auto urlGroup = session.CreateUrlGroup();
	urlGroup.Bind(queue);
	urlGroup.SetTimeout(50);

	wprintf(L"we are listening for requests on the following url: %s\n", url);

	urlGroup.AddUrl(url);

	queue.ReceiveRequests(wwwAuthVal);

	return 0;
}
