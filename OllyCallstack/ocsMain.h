#include <windows.h>
#include <DbgHelp.h>

#include "OllyPluginHeader.h"

#define PLUGINNAME     L"OllyCallstack"		// Unique plugin name
#define VERSION        L"1.0"				// Plugin version

HINSTANCE        hdllinst;					// Instance of plugin DLL

int ocsShowCallstackTable(t_table *pt,wchar_t *name,ulong index,int mode);
int ocsUpdateCallstackTable(t_table *pt,wchar_t *name,ulong index,int mode);
int ocsDrawCallstackTable(wchar_t *s,uchar *mask,int *select,t_table *pt,t_drawheader *ph,int column,void *cache);

long ocsTableTabFunc(t_table *pt,HWND hw,UINT msg,WPARAM wp,LPARAM lp);

static t_menu mainmenu[] = {
	// <Display in Menu> <Description in state bar>		< Callback of user cklicks our plugin>
	{ L"View Callstack",L"Shows the Callstack Window",K_NONE,ocsShowCallstackTable,NULL,0 },{NULL,NULL,K_NONE,NULL,NULL,0 }
};

typedef struct t_OCTTable {
	ulong          index;  // Must have!
	ulong          size;   // Must have!
	ulong          type;   // Must have!

	DWORD			dwStackAddr; // Our address in the stack
	DWORD			dwRetAddr;   // Return address of this stackframe
	DWORD			dwFuncAddr;  // Function which got executed in this frame
} t_OCTTable;

static t_table   OCTTable;             // Bookmark table