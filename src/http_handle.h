#pragma once
#define SECURITY_WIN32

#include <http.h>
#include <Windows.h>
#include <winrt/base.h>
#include <wrl/wrappers/corewrappers.h>


using winrt::check_win32;

// Handle specializations for implemented RAII wrappers
struct SessionTraits
{
	using Type = HTTP_SERVER_SESSION_ID;

	static bool Close(Type h) noexcept
	{
		return HttpCloseServerSession(h) == NO_ERROR;
	}

	static Type GetInvalidValue() noexcept
	{
		return HTTP_NULL_ID;
	}
};

struct UrlGroupTraits
{
	using Type = HTTP_URL_GROUP_ID;

	static bool Close(Type h) noexcept
	{
		return HttpRemoveUrlFromUrlGroup(h, nullptr, HTTP_URL_FLAG_REMOVE_ALL) == NO_ERROR &&
			HttpCloseUrlGroup(h) == NO_ERROR;
	}

	static Type GetInvalidValue() noexcept
	{
		return HTTP_NULL_ID;
	}
};

struct RequestQueueTraits
{
	using Type = HANDLE;

	static bool Close(Type h) noexcept
	{
		return HttpCloseRequestQueue(h) == NO_ERROR;
	}

	static Type GetInvalidValue() noexcept
	{
		return nullptr;
	}
};

using SessionHandle = Microsoft::WRL::Wrappers::HandleT<SessionTraits>;
using UrlGroupHandle = Microsoft::WRL::Wrappers::HandleT<UrlGroupTraits>;
using RequestQueueHandle = Microsoft::WRL::Wrappers::HandleT<RequestQueueTraits>;