#define WIN32_NO_STATUS
#include <Windows.h>
#include <stdio.h>
#include <Winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

// Object manager specific access rights from wdm.h
#define DIRECTORY_QUERY                 (0x0001)
#define DIRECTORY_TRAVERSE              (0x0002)

// Struct definition from MSDN's help for NtQueryDirectoryObject (no header file)
typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

// ntdll.dll internal functions without header
typedef VOID(WINAPI *_RtlInitUnicodeString)(
	_Inout_  PUNICODE_STRING DestinationString,
	_In_opt_ PCWSTR          SourceString
	);
typedef NTSTATUS (WINAPI *_NtOpenDirectoryObject)(
	_Out_ PHANDLE            DirectoryHandle,
	_In_  ACCESS_MASK        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES ObjectAttributes
);
typedef NTSTATUS (WINAPI *_NtQueryDirectoryObject)(
	_In_      HANDLE  DirectoryHandle,
	_Out_opt_ PVOID   Buffer,
	_In_      ULONG   Length,
	_In_      BOOLEAN ReturnSingleEntry,
	_In_      BOOLEAN RestartScan,
	_Inout_   PULONG  Context,
	_Out_opt_ PULONG  ReturnLength
);
typedef NTSTATUS (WINAPI *_NtOpenSymbolicLinkObject)(
	_Out_ PHANDLE            LinkHandle,
	_In_  ACCESS_MASK        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES ObjectAttributes
);
typedef NTSTATUS (WINAPI *_NtQuerySymbolicLinkObject)(
	_In_      HANDLE          LinkHandle,
	_Inout_   PUNICODE_STRING LinkTarget,
	_Out_opt_ PULONG          ReturnedLength
);

typedef struct _obj_entry_t {
	SIZE_T entrySize;
	SIZE_T childObjCount;
	PWSTR pwszName;
	PWSTR pwszTypeName;
	PWSTR pwszSymlinkTarget;
	struct _obj_entry_t *pChildObj[1];
} obj_entry_t;

// Global function pointers

static _RtlInitUnicodeString pRtlInitUnicodeString = NULL;
static _NtOpenDirectoryObject pNtOpenDirectoryObject = NULL;
static _NtQueryDirectoryObject pNtQueryDirectoryObject = NULL;
static _NtOpenSymbolicLinkObject pNtOpenSymbolicLinkObject = NULL;
static _NtQuerySymbolicLinkObject pNtQuerySymbolicLinkObject = NULL;

/**
 * Comparison function to sort objects by type, then by name
 */
int cmp_obj_type_and_names(obj_entry_t *a, obj_entry_t *b)
{
	int res = _wcsicmp(a->pwszTypeName, b->pwszTypeName);
	if (res == 0)
		res = _wcsicmp(a->pwszName, b->pwszName);
	return res;
}

/**
 * Comparison function to sort objects by name
 */
int cmp_obj_names(obj_entry_t *a, obj_entry_t *b)
{
	return _wcsicmp(a->pwszName, b->pwszName);
}

/**
 * Insertion sort applied to all child objects of the given directory,
 * using the given comparison function (which must take two pointers
 * to obj_entry_t and return a <0 , =0 or >0 int).
 */
VOID sort_child_objects_by(obj_entry_t *root, int (*cmp_func)(obj_entry_t*, obj_entry_t*))
{
	for (SIZE_T i = 1; i < root->childObjCount; i++)
	{
		obj_entry_t *to_insert = root->pChildObj[i];
		SIZE_T j = i;
		while (j > 0 && cmp_func(root->pChildObj[j-1], to_insert) >= 0)
		{
			root->pChildObj[j] = root->pChildObj[j-1];
			j--;
		}
		root->pChildObj[j] = to_insert;
	}
}

PVOID safe_alloc(SIZE_T bytes)
{
	void *res = calloc(bytes, 1);
	if (res == NULL)
	{
		printf(" [!] Out of memory\n");
		exit(1);
	}
	return res;
}

PVOID safe_realloc(PVOID buffer, SIZE_T bytes)
{
	PVOID res = realloc(buffer, bytes);
	if (res == NULL)
	{
		printf(" [!] Out of memory\n");
		exit(1);
	}
	return res;
}

int scanDirectory(HANDLE hParentDir, PCWSTR pcwDirname, obj_entry_t **parentObj, BOOL bRecurse)
{
	int res = 0;
	UNICODE_STRING usObjName = { 0 };
	OBJECT_ATTRIBUTES objAttr = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hObjDir = NULL;
	HANDLE hSymLink = NULL;
	ULONG ulQueryContext = 0;
	SIZE_T objInfoSize = 0x1000;
	POBJECT_DIRECTORY_INFORMATION pObjInfo = safe_alloc(objInfoSize);

	if (pcwDirname == NULL || parentObj == NULL || *parentObj == NULL)
		return EINVAL;

	if ((*parentObj)->pwszName == NULL)
	{
		(*parentObj)->pwszName = safe_alloc((wcslen(pcwDirname) + 1) * sizeof(wchar_t));
		wcscpy_s((*parentObj)->pwszName, wcslen(pcwDirname) + 1, pcwDirname);
	}
	if ((*parentObj)->pwszTypeName == NULL)
	{
		(*parentObj)->pwszTypeName = safe_alloc((wcslen(L"Directory") + 1) * sizeof(wchar_t));
		wcscpy_s((*parentObj)->pwszTypeName, wcslen(L"Directory") + 1, L"Directory");
	}

	pRtlInitUnicodeString(&usObjName, pcwDirname);
	InitializeObjectAttributes(&objAttr, &usObjName, 0, hParentDir, NULL);

	status = pNtOpenDirectoryObject(&hObjDir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &objAttr);
	if (NT_ERROR(status))
	{
		res = status;
		fprintf(stderr, " [!] NtOpenDirectoryObject(): code %ld\n", res);
		goto cleanup;
	}

	while (1)
	{
		ZeroMemory(pObjInfo, objInfoSize);
		status = pNtQueryDirectoryObject(hObjDir, pObjInfo, (ULONG)objInfoSize, TRUE, FALSE, &ulQueryContext, NULL);
		if (status == STATUS_BUFFER_TOO_SMALL)
		{
			objInfoSize *= 2;
			pObjInfo = safe_realloc(pObjInfo, objInfoSize);
			continue;
		}
		else if (NT_ERROR(status))
		{
			res = status;
			fprintf(stderr, " [!] NtQueryDirectoryObject(): code %ld\n", res);
			goto cleanup;
		}
		else if (pObjInfo->TypeName.Length == 0 || pObjInfo->Name.Length == 0)
		{
			break;
		}

		obj_entry_t *childObj = safe_alloc(sizeof(obj_entry_t));
		childObj->entrySize = sizeof(obj_entry_t);

		childObj->pwszName = safe_alloc(pObjInfo->Name.Length + sizeof(wchar_t));
		childObj->pwszTypeName = safe_alloc(pObjInfo->TypeName.Length + sizeof(wchar_t));
		wcscpy_s(childObj->pwszName, pObjInfo->Name.Length / 2 + sizeof(wchar_t), pObjInfo->Name.Buffer);
		wcscpy_s(childObj->pwszTypeName, pObjInfo->TypeName.Length / 2 + sizeof(wchar_t), pObjInfo->TypeName.Buffer);

		if (_wcsicmp(childObj->pwszTypeName, L"Directory") == 0 && bRecurse)
		{
			res = scanDirectory(hObjDir, childObj->pwszName, &childObj, bRecurse);
			if (res != 0)
			{
				fprintf(stderr, " [!] Failed to scan subdirectory %S (code %ld)\n", childObj->pwszName, res);
			}
		}
		else if (_wcsicmp(childObj->pwszTypeName, L"SymbolicLink") == 0)
		{
			UNICODE_STRING usSymLinkName = { 0 };
			UNICODE_STRING usSymLinkTarget = { 0 };
			ULONG ulTargetLen = 0;
			OBJECT_ATTRIBUTES symLinkAttr = { 0 };
			
			usSymLinkTarget.Length = usSymLinkTarget.MaximumLength = 0;
			pRtlInitUnicodeString(&usSymLinkName, childObj->pwszName);
			InitializeObjectAttributes(&symLinkAttr, &usSymLinkName, 0, hObjDir, NULL);
			status = pNtOpenSymbolicLinkObject(&hSymLink, GENERIC_READ, &symLinkAttr);
			if (NT_ERROR(status))
			{
				res = status;
				fprintf(stderr, " [!] NtOpenSymbolicLinkObject(): code %ld\n", res);
				goto cleanup; 
			}

			status = pNtQuerySymbolicLinkObject(hSymLink, &usSymLinkTarget, &ulTargetLen);
			if (status != STATUS_BUFFER_TOO_SMALL || ulTargetLen == 0 || ulTargetLen >= USHRT_MAX)
			{
				res = (status == STATUS_SUCCESS ? -1 : status);
				fprintf(stderr, " [!] NtQuerySymbolicLinkObject(): code %ld\n", res);
				goto cleanup;
			}

			usSymLinkTarget.Buffer = safe_alloc(ulTargetLen);
			usSymLinkTarget.Length = 0;
			usSymLinkTarget.MaximumLength = (USHORT)ulTargetLen;

			status = pNtQuerySymbolicLinkObject(hSymLink, &usSymLinkTarget, &ulTargetLen);
			if (NT_ERROR(status))
			{
				res = status;
				fprintf(stderr, " [!] NtQuerySymbolicLinkObject(): code %ld\n", res);
				goto cleanup;
			}

			ulTargetLen = usSymLinkTarget.Length + sizeof(wchar_t);
			childObj->pwszSymlinkTarget = safe_alloc(ulTargetLen);
			wcsncpy_s(childObj->pwszSymlinkTarget, ulTargetLen/2, usSymLinkTarget.Buffer, ulTargetLen/2 - 1);

			CloseHandle(hSymLink);
			hSymLink = NULL;
		}

		*parentObj = safe_realloc(*parentObj, (*parentObj)->entrySize + sizeof(void*));
		(*parentObj)->entrySize += sizeof(void*);
		(*parentObj)->pChildObj[(*parentObj)->childObjCount] = childObj;
		(*parentObj)->childObjCount++;
	}

	sort_child_objects_by(*parentObj, &cmp_obj_names);

cleanup:
	if (hObjDir != NULL)
		CloseHandle(hObjDir);
	if (hSymLink != NULL)
		CloseHandle(hSymLink);
	return res;
}

void printEntry(obj_entry_t *obj, int depth, int last)
{
	printf("%20S  ", obj->pwszTypeName);
	for (int i = 0; i < depth - 1; i++)
		printf("\xB3  ");
	if (depth > 0)
		printf("%c\xC4 ", (last ? '\xC0' : '\xC3'));
	printf("%S", obj->pwszName);
	if (_wcsicmp(obj->pwszTypeName, L"SymbolicLink") == 0)
	{
		printf(" -> %S", obj->pwszSymlinkTarget);
	}
	printf("\n");
	for (SIZE_T i = 0; i < obj->childObjCount; i++)
		printEntry(obj->pChildObj[i], depth + 1, (i == obj->childObjCount - 1));
}

void printDirectory(obj_entry_t *objDir)
{
	printEntry(objDir, 0, 1);
}

int wmain(int argc, wchar_t *argv[])
{
	int res = 0;
	HANDLE hNtdll = NULL;
	PWSTR pwzTarget = L"\\";
	SIZE_T targetLen = 1;
	BOOL bRecurse = FALSE;
	obj_entry_t *rootObj = NULL;

	hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll == NULL)
	{
		res = GetLastError();
		fprintf(stderr, " [!] GetModuleHandle(): code %ld\n", res);
		goto cleanup;
	}
	
	pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");
	if (pRtlInitUnicodeString == NULL)
	{
		res = GetLastError();
		fprintf(stderr, " [!] GetProcAddress(ntdll, RtlInitUnicodeString): code %ld\n", res);
		goto cleanup;
	}

	pNtOpenDirectoryObject = (_NtOpenDirectoryObject)GetProcAddress(hNtdll, "NtOpenDirectoryObject");
	if (pNtOpenDirectoryObject == NULL)
	{
		res = GetLastError();
		fprintf(stderr, " [!] GetProcAddress(ntdll, NtOpenDirectoryObject): code %ld\n", res);
		goto cleanup;
	}

	pNtQueryDirectoryObject = (_NtQueryDirectoryObject)GetProcAddress(hNtdll, "NtQueryDirectoryObject");
	if (pNtQueryDirectoryObject == NULL)
	{
		res = GetLastError();
		fprintf(stderr, " [!] GetProcAddress(ntdll, NtQueryDirectoryObject): code %ld\n", res);
		goto cleanup;
	}

	pNtOpenSymbolicLinkObject = (_NtOpenSymbolicLinkObject)GetProcAddress(hNtdll, "NtOpenSymbolicLinkObject");
	if (pNtOpenSymbolicLinkObject == NULL)
	{
		res = GetLastError();
		fprintf(stderr, " [!] GetProcAddress(ntdll, NtOpenSymbolicLinkObject): code %ld\n", res);
		goto cleanup;
	}

	pNtQuerySymbolicLinkObject = (_NtQuerySymbolicLinkObject)GetProcAddress(hNtdll, "NtQuerySymbolicLinkObject");
	if (pNtQuerySymbolicLinkObject == NULL)
	{
		res = GetLastError();
		fprintf(stderr, " [!] GetProcAddress(ntdll, NtQuerySymbolicLinkObject): code %ld\n", res);
		goto cleanup;
	}

	if (argc >= 2 && _wcsicmp(argv[1], L"-R") == 0)
	{
		bRecurse = TRUE;
		argc--;
		argv[1] = argv[0];
		argv++;
	}

	if (argc == 2)
		pwzTarget = argv[1];

	targetLen = wcslen(pwzTarget);
	if (targetLen == 0)
		pwzTarget = L"\\";
	else if (targetLen > 1 && pwzTarget[targetLen - 1] == L'\\')
		pwzTarget[targetLen - 1] = L'\0';

	rootObj = safe_alloc(sizeof(*rootObj));
	rootObj->entrySize = sizeof(*rootObj);
	
	res = scanDirectory(NULL, pwzTarget, &rootObj, bRecurse);
	if (res != 0)
		goto cleanup;

	printDirectory(rootObj);

cleanup:
	return res;
}