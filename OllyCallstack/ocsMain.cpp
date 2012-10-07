#include "ocsMain.h"

BOOL WINAPI DllEntryPoint(HINSTANCE hi,DWORD dwReason,LPVOID lpReserved) {
	if (dwReason == DLL_PROCESS_ATTACH)
		hdllinst = hi;
	return 1;
}

// Function which returns the menu we created for the OllyMain Window
extc t_menu * __cdecl ODBG2_Pluginmenu(wchar_t *type)
{
	if (wcscmp(type,PWM_MAIN) == 0)
		return mainmenu; // Return our Menu if called from the mainwindow
	return NULL; // Else no menu will be displayed from us
}

// Function to give plugin information to olly and check olly version
extc int __cdecl ODBG2_Pluginquery(int ollydbgversion,ulong *features,wchar_t pluginname[SHORTNAME],wchar_t pluginversion[SHORTNAME])
{
		if (ollydbgversion < 201)
			return 0; // Disable plugin if ollyversion is too old
		StrcopyW(pluginname,SHORTNAME,PLUGINNAME); // copy plugin name to olly
		StrcopyW(pluginversion,SHORTNAME,VERSION); // copy plugin version to olly
		return PLUGIN_VERSION; // Return our plugin version
}

// Function which get called on olly startup
extc int __cdecl ODBG2_Plugininit(void)
{
	// Create a sorted table for our stackwalk data
	if (Createsorteddata(&OCTTable.sorted,sizeof(OCTTable),1,NULL,NULL,NULL) != 0)
		return -1;

	// Setup our table for the stackwalk data
	StrcopyW(OCTTable.name,SHORTNAME,PLUGINNAME);
	OCTTable.mode = TABLE_SAVEALL;
	OCTTable.bar.visible = 1;
	OCTTable.bar.name[0] = L"Stack <Offset>";
	OCTTable.bar.expl[0] = L"";
	OCTTable.bar.mode[0] = BAR_SORT;
	OCTTable.bar.defdx[0] = 15;
	OCTTable.bar.name[1] = L"Function <Address>";
	OCTTable.bar.expl[1] = L"";
	OCTTable.bar.mode[1] = BAR_SORT; // Could call sort callback in the table if user clicks it. Needs to be set in Createsorteddata
	OCTTable.bar.defdx[1] = 30;			
	OCTTable.bar.name[2] = L"Function <Symbol>";
	OCTTable.bar.expl[2] = L"";
	OCTTable.bar.mode[2] = BAR_FLAT; // Default no callbacks / handlers
	OCTTable.bar.defdx[2] = 40;
	OCTTable.bar.name[3] = L"Called From <Address>";
	OCTTable.bar.expl[3] = L"";
	OCTTable.bar.mode[3] = BAR_FLAT;
	OCTTable.bar.defdx[3] = 30;
	OCTTable.bar.name[4] = L"Called From <Symbol>";
	OCTTable.bar.expl[4] = L"";
	OCTTable.bar.mode[4] = BAR_FLAT;
	OCTTable.bar.defdx[4] = 40;
	OCTTable.bar.nbar = 5;
	OCTTable.custommode = 0;
	OCTTable.customdata = NULL;
	OCTTable.updatefunc = NULL;
	OCTTable.tabfunc = (TABFUNC*)ocsTableTabFunc; // Callback for handling window message to the display table ( left click , right click etc.. )
	OCTTable.drawfunc = (DRAWFUNC*)ocsDrawCallstackTable; // Callback to fill the table with data when we press the plugin button in olly
	OCTTable.tableselfunc = NULL;
	OCTTable.menu = NULL;

	return 0;
}

// Function which get called if target is closed/reloaded
extc void __cdecl ODBG2_Pluginreset(void)
{
	// Target gets restarted via olly so we remove all data we saved
	Deletesorteddatarange(&OCTTable.sorted,0,0xFFFFFFFF);
}

// Function which get called if olly is closed
extc void __cdecl ODBG2_Plugindestroy(void) 
{
	// Olly gets closed so free our tabel
	Destroysorteddata(&OCTTable.sorted);
}

// Function which get called if user clicks on our plugin menu
int ocsUpdateCallstackTable(t_table *pt,wchar_t *name,ulong index,int mode) 
{
	t_run runState = run;

	// Display new call stack, cleaning previous data
	Deletesorteddatarange(&OCTTable.sorted,0,0xFFFFFFFF);

	// Get needed handles to walk the stack
	HANDLE	hProc = OpenProcess(PROCESS_ALL_ACCESS,false,run.de.dwProcessId),
			hThread = OpenThread(THREAD_ALL_ACCESS,false,run.de.dwThreadId);

	if( hProc == INVALID_HANDLE_VALUE || hThread == INVALID_HANDLE_VALUE)
		return 0; // INVALID HANDLE == no stackwalk - so return nothing
		
	int iIndexCounter = NULL;		
	STACKFRAME64 stackFr = {0};

	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread,&context); // Get ThreadContext to get eip , ebp , esp for stackwalk

	// init StackFrame Struct for StackWalk64;
	stackFr.AddrPC.Offset = context.Eip;
	stackFr.AddrPC.Mode = AddrModeFlat;
	stackFr.AddrFrame.Offset = context.Ebp;
	stackFr.AddrFrame.Mode = AddrModeFlat;
	stackFr.AddrStack.Offset = context.Esp;
	stackFr.AddrStack.Mode = AddrModeFlat;

	BOOL bSuccess;
	do
	{
		// Perform a stackwalk in hProc,hThread
		bSuccess = StackWalk64(IMAGE_FILE_MACHINE_I386,hProc,hThread,&stackFr,&context,NULL,SymFunctionTableAccess64,SymGetModuleBase64,0);

		if(!bSuccess)        
			break;

		t_OCTTable newData; // Save the data of the found stackframe to our TableStruct
		newData.index = iIndexCounter++;
		newData.size = 1;
		newData.type = 0;
		newData.dwFuncAddr = stackFr.AddrPC.Offset;
		newData.dwStackAddr = stackFr.AddrStack.Offset;
		newData.dwRetAddr = stackFr.AddrReturn.Offset;
		Addsorteddata(&OCTTable.sorted,&newData);

	}while (stackFr.AddrReturn.Offset != 0); // Search stackframe until return is 0 - last stackframe found

	return MENU_REDRAW; // We got our data so tell olly to redraw the table with the new data
}

// Function which gets called if we click the Plugin Menu in Olly
int ocsShowCallstackTable(t_table *pt,wchar_t *name,ulong index,int mode)
{
	if (mode == MENU_VERIFY)
		return MENU_NORMAL;
	else if (mode == MENU_EXECUTE) // Our Plugin menu got clicked
	{
		t_run runState = run;
		if(runState.status == STAT_PAUSED) // Check if target is suspended
		{
			if (OCTTable.hw == NULL) // If we don´t have a table until now create a new
				Createtablewindow(&OCTTable,0,OCTTable.bar.nbar,NULL,L"ICO_P",PLUGINNAME);
			else
				Activatetablewindow(&OCTTable); // We already have a table so use this

			return ocsUpdateCallstackTable(pt,name,index,mode); // Fill new data into our table
		}
		else
			MessageBoxW(NULL,L"ERROR: Target must be in suspended Mode!",PLUGINNAME,MB_OK);
		return MENU_NOREDRAW; // Error , don´t update the display
	}
	return MENU_ABSENT;
}

// Function to fill in the data into our display table
// Gets called for each row and column we filled in our table(t_OCTTable)
int ocsDrawCallstackTable(wchar_t *s,uchar *mask,int *select,t_table *pt,t_drawheader *ph,int column,void *cache) 
{
	DWORD	dwStrLen = NULL;
	t_OCTTable *pmark = (t_OCTTable*)ph;

	switch (column) // Check which column olly is about to draw and fill the data we need
	{
	case 0:	// Stack Addr
		dwStrLen = Simpleaddress(s,pmark->dwStackAddr,mask,select); // Copy address to string (s)
		break;
	case 1: // Func Addr
		dwStrLen = Simpleaddress(s,pmark->dwFuncAddr,mask,select);
		break;
	case 2: // Func Symbol
		dwStrLen = Decoderelativeoffset(pmark->dwFuncAddr,DM_SYMBOL,s,TEXTLEN); // Decode the address to a symbol
		if(dwStrLen <= 0)
			dwStrLen = Decodeaddress(pmark->dwFuncAddr,NULL,DM_SYMBOL,s,TEXTLEN,NULL);
		break;
	case 3: // Ret Addr
		dwStrLen = Simpleaddress(s,pmark->dwRetAddr,mask,select);
		break;
	case 4: // Ret Symbol
		dwStrLen = Decoderelativeoffset(pmark->dwRetAddr,DM_SYMBOL,s,TEXTLEN);
		if(dwStrLen <= 0)
			dwStrLen = Decodeaddress(pmark->dwFuncAddr,NULL,DM_SYMBOL,s,TEXTLEN,NULL);
		break;
	default:
		break;
	}
	return dwStrLen; // return the data len to olly
}

// Function to handle the window messages of our display table
long ocsTableTabFunc(t_table *pt,HWND hw,UINT msg,WPARAM wp,LPARAM lp)
{
	t_OCTTable *pTableData;
	switch (msg)
	{
	case WM_USER_DBLCLK:
		// Double kcick in our display table
		// Show selected offset in disassambly view
		pTableData = (t_OCTTable*)Getsortedbyselection(&pt->sorted,pt->sorted.selected);
		if (pTableData != NULL)
			Setcpu(0,pTableData->dwFuncAddr,0,0,0,CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS);
		return 1;
	default: 
		break;
	}
	return 0;
};