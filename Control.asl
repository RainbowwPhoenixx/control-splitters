//By MrLette, based off Wangler auto-start/load remover. Anyone is free to host, fork or modify the following code.

state("Control_DX11", "DX11") { }
state("Control_DX12", "DX12") { }

startup
{
    vars.gameTarget = new SigScanTarget(3,
        "48 8B 05 ????????",  // mov  rax, [Control_DX1#.exe+????????]
        "48 8B 48 30",        // mov  rcx, [rax+30]
        "80 B9 ???????? 00"); // cmp  byte ptr [rcx+?], 00

    vars.inputManagerTarget = new SigScanTarget(10, "48 89 86 ?? ?? 00 00 48 89 35"); // signature to get InputManager instance pointer
	vars.completeMissionFunctionAddressSig = new SigScanTarget(0, "49 8B CE 84 C0 74 54 48 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 49 8B CE"); //Signature to get CompleteMission function (search for "CompleteMission" string Xref in IDA, offset is 0x5246E3 in 0.96)
	vars.getInstanceSig = new SigScanTarget(5, "33 C0 48 8D 0D ?? ?? ?? ?? 48 8B 04 08 C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 4C 24 08"); //Signature to coreflow::Systems::getInstance(), used to get the pointer to coreflow::Systems::sm_instances
	vars.completeObjectiveFunctionAddressSig = new SigScanTarget(1, "57 41 56 41 57 48 83 EC 20 45 0F B6 F9 49 8B F8 4C 8B F2 48 8B F1 E8");//Siganture to the function called by CompleteStep 
	vars.FreeMemory = (Action<Process>)(p =>
    {
        p.FreeMemory((IntPtr)vars.hookBytecodeCave);
		p.FreeMemory((IntPtr)vars.objectiveHookBytecodeCave);
    });

	settings.Add("intro_subsplits", false, "Additional subsplits for intro & unknown caller");
}

init
{
    vars.isFoundationPatch = modules.First().ModuleMemorySize >= 20418560; // foundation patch exe size, may break in the future

    var module = modules.First();
    var inputStr = module.ModuleName == "Control_DX11.exe" ? "input_rmdwin7_f.dll" : "input_rmdwin10_f.dll";
	var rlStr = module.ModuleName == "Control_DX11.exe" ? "rl_rmdwin7_f.dll" : "rl_rmdwin10_f.dll";

    var scanner = new SignatureScanner(game, module.BaseAddress, module.ModuleMemorySize);
    var gameScan = scanner.Scan((SigScanTarget)vars.gameTarget);

    var inputModule = modules.Single(m => m.ModuleName == inputStr);
    var imScanner = new SignatureScanner(game, inputModule.BaseAddress, inputModule.ModuleMemorySize);
    var imScan = imScanner.Scan((SigScanTarget)vars.inputManagerTarget);

	var rlModule = modules.Single(m => m.ModuleName == rlStr);
	var rlScanner = new SignatureScanner(game, rlModule.BaseAddress, rlModule.ModuleMemorySize);
	
    var offset = game.ReadValue<int>(gameScan);
    var imOffset = game.ReadValue<int>(imScan);
    var loadingOffset = game.ReadValue<int>(gameScan + 10);

    if (vars.isFoundationPatch)
        loadingOffset += 3;

    Thread.Sleep(2500); // Give the game a chance to initialize..

    // Boolean for loading
    vars.isLoading = new MemoryWatcher<bool>(new DeepPointer(module.ModuleName, (int)((long)(gameScan + offset + 4) - (long)module.BaseAddress), 0x30, loadingOffset));

    // ClientState hash
    vars.state = new MemoryWatcher<uint>(new DeepPointer(module.ModuleName, (int)((long)(gameScan + offset + 4) - (long)module.BaseAddress), 0x30, vars.isFoundationPatch ? 0x138 : 0x1A8));

    // InputManager.playerControlEnabled
    vars.playerControlEnabled = new MemoryWatcher<bool>(new DeepPointer(inputModule.ModuleName, (int)((long)(imScan + imOffset + 4) - (long)inputModule.BaseAddress), vars.isFoundationPatch ? 0x7D : 0x8D));


	vars.completeMissionFunctionAddress = scanner.Scan((SigScanTarget)vars.completeMissionFunctionAddressSig);
	if (vars.completeMissionFunctionAddress == IntPtr.Zero)
		throw new Exception("Can't find completeMission function address");
	vars.completeMissionFunctionAddress = (IntPtr)vars.completeMissionFunctionAddress;
	var jmpInstructionSize = 12; //x64 creates 12 bytes instructions, 10 bytes to mov the addr to rax then 2 bytes for jmp'ing to rax
	var overridenBytesForTrampoline = 14; //See the 4 original instructions below 
	
	//Original code copied (comment based on 0.96) :
	//	0x49 ,0x8B, 0xCE, 							mov rcx,r14
	//	0x84, 0xC0,       							test al,al
	//	0x74, 0x54,		  							je Control_DX11.exe+52474A
	//	0x48, 0x8D, 0x95, 0xC0, 0x05, 0x00, 0x00 	lea rdx,[rbp+000005C0]
	vars.originalMissionCompleteFunctionCode = game.ReadBytes((IntPtr)vars.completeMissionFunctionAddress, overridenBytesForTrampoline);
	
	//Bytecode that executes the code overrided by the trampoline jmp + sets a boolean to true and stores mission GID in our newly allocated memory when called
	var missionCompleteHookBytecode = new List<byte> {0x58}; //pop rax (restore saved rax)
	missionCompleteHookBytecode.AddRange((byte[])vars.originalMissionCompleteFunctionCode); //Adding original code
	missionCompleteHookBytecode.AddRange(new byte[] {0x8B, 0x41, 0x10}); //mov eax,[rcx+10]
	missionCompleteHookBytecode.AddRange(new byte[] {0x89, 0x05, 0x20, 0x00, 0x00, 0x00}); //mov [rip+32],eax Storing current mission GID
	missionCompleteHookBytecode.AddRange(new byte[] {0xC6, 0x05, 0x18, 0x00, 0x00, 0x00, 0x01}); //mov byte ptr[rip+24],0x01 (our instruction to set our boolean to true on execution)
	missionCompleteHookBytecode.AddRange(new byte[(jmpInstructionSize * 2) + 1 + 4] ); //We need 2 jumps, one for each branch of the "test al,al" instruction copied from the original code + 1 byte for our bool storage + 4 byte for mission GID storage

	vars.hookBytecodeCave = game.AllocateMemory(missionCompleteHookBytecode.Count);
	vars.isMissionCompletedAddress = (IntPtr)vars.hookBytecodeCave + missionCompleteHookBytecode.Count - 5;
	vars.isMissionCompleted = new MemoryWatcher<bool>(vars.isMissionCompletedAddress);

	vars.completeObjectiveFunctionAddress = scanner.Scan((SigScanTarget)vars.completeObjectiveFunctionAddressSig);
	if (vars.completeObjectiveFunctionAddress == IntPtr.Zero)
		throw new Exception("Can't find completeStep function address");
	var overridenBytesForObjectiveTrampoline = 12;
	//Original code copied (comment based on 0.96) :
	//Control_DX11.exe+3EFD8B - 41 56                 - push r14
	//Control_DX11.exe+3EFD8D - 41 57                 - push r15
	//Control_DX11.exe+3EFD8F - 48 83 EC 20           - sub rsp,20
	//Control_DX11.exe+3EFD93 - 45 0FB6 F9            - movzx r15d,r9l

	vars.originalObjectiveCompleteFunctionCode = game.ReadBytes((IntPtr)vars.completeObjectiveFunctionAddress, overridenBytesForObjectiveTrampoline);
	
	//Bytecode that executes the code overrided by the trampoline jmp + stores latest objective hash in our newly allocated memory when called
	var objectiveCompleteHookBytecode = new List<byte>((byte[])vars.originalObjectiveCompleteFunctionCode);
	objectiveCompleteHookBytecode.AddRange(new byte[] {0x49, 0x8b, 0x38}); //mov  rdi,QWORD PTR [r8]
	objectiveCompleteHookBytecode.AddRange(new byte[] {0x48, 0x89, 0x3D, 0x0C, 0x00, 0x00, 0x00}); //mov QWORD PTR [rip+0xc],rdi
	objectiveCompleteHookBytecode.AddRange(new byte[jmpInstructionSize + 8] ); //We need one jump + 8 bytes for storing objective hash

	vars.objectiveHookBytecodeCave = game.AllocateMemory(objectiveCompleteHookBytecode.Count);
	vars.latestObjectiveHashAddress = (IntPtr)vars.objectiveHookBytecodeCave + objectiveCompleteHookBytecode.Count - 8;
	vars.latestObjectiveHash = new MemoryWatcher<UInt64>(vars.latestObjectiveHashAddress);

	game.Suspend();
	try {		
		//Writing hook function into memory
		game.WriteBytes((IntPtr)vars.hookBytecodeCave, missionCompleteHookBytecode.ToArray());
		game.WriteJumpInstruction((IntPtr)vars.hookBytecodeCave + missionCompleteHookBytecode.Count - ((jmpInstructionSize * 2) + 5), (IntPtr)vars.completeMissionFunctionAddress + overridenBytesForTrampoline); //Set jump back to inside if on original function (je not executed)
		game.WriteJumpInstruction((IntPtr)vars.hookBytecodeCave + missionCompleteHookBytecode.Count - (jmpInstructionSize + 5), (IntPtr)vars.completeMissionFunctionAddress + 0x54 + 7); //Set jump back to outside if on original function (je executed)
		game.WriteBytes((IntPtr)vars.isMissionCompletedAddress, new byte[] {0x00}); //Make sure our boolean starts set to false
		game.WriteBytes((IntPtr)vars.hookBytecodeCave + 7, new byte[] {0x23}); //Patching the je offset from original code to point to our second jmp
		
		//Placing trampoline on original function
		game.WriteBytes((IntPtr)vars.completeMissionFunctionAddress, new byte[] {0x50}); //push rax
		game.WriteJumpInstruction((IntPtr)vars.completeMissionFunctionAddress + 1, (IntPtr)vars.hookBytecodeCave); //injecting the 12 bytes trampoline jmp to our hook codecave
		game.WriteBytes((IntPtr)vars.completeMissionFunctionAddress + 1 + jmpInstructionSize, new byte[] {0x90}); //nop the last byte
		
		//Writing hook function into memory
		game.WriteBytes((IntPtr)vars.objectiveHookBytecodeCave, objectiveCompleteHookBytecode.ToArray());
		game.WriteJumpInstruction((IntPtr)vars.objectiveHookBytecodeCave + objectiveCompleteHookBytecode.Count - (jmpInstructionSize + 8), (IntPtr)vars.completeObjectiveFunctionAddress + overridenBytesForObjectiveTrampoline); //Set jump back to outside if on original function
		game.WriteBytes((IntPtr)vars.latestObjectiveHashAddress, new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
		
		//Placing trampoline on original function
		game.WriteJumpInstruction((IntPtr)vars.completeObjectiveFunctionAddress, (IntPtr)vars.objectiveHookBytecodeCave); //injecting the 12 bytes trampoline jmp to our hook codecave
	}
	catch {
		vars.FreeMemory(game);
		game.WriteBytes((IntPtr)vars.completeMissionFunctionAddress, (byte[])vars.originalMissionCompleteFunctionCode); //Restore original bytecode
		game.WriteBytes((IntPtr)vars.completeObjectiveFunctionAddress, (byte[])vars.originalObjectiveCompleteFunctionCode); //Restore original bytecode
		throw new Exception("Something went wrong when placing hooks");
	}
	finally {
		game.Resume();
	}
	
	var sm_instancesptr = rlScanner.Scan((SigScanTarget)vars.getInstanceSig);
	var sm_instances_offset = game.ReadValue<int>(sm_instancesptr);
	vars.sm_instances = sm_instancesptr + 4 + sm_instances_offset;

	vars.autoEndNext = false; //probs need to clear this elsewhere too
}

update
{

	vars.isLoading.Update(game);
	vars.state.Update(game);

	if (settings.StartEnabled || settings.SplitEnabled) {
		vars.playerControlEnabled.Update(game);
	}
	
	if (settings.SplitEnabled) {
		vars.isMissionCompleted.Update(game);
		vars.latestObjectiveHash.Update(game);
	}
	
	if (vars.state.Current != vars.state.Old || vars.playerControlEnabled.Current != vars.playerControlEnabled.Old || vars.isLoading.Current != vars.isLoading.Old || vars.isMissionCompleted.Current != vars.isMissionCompleted.Old || vars.latestObjectiveHash.Current != vars.latestObjectiveHash.Old) {
		print("vars.state " + ((UInt64)vars.state.Current).ToString("X") + " - vars.playerControlEnabled " + (vars.playerControlEnabled.Current).ToString() + " - vars.isLoading " + (vars.isLoading.Current).ToString() + " - vars.isMissionCompleted " + (vars.isMissionCompleted.Current).ToString());
	}
	if (vars.latestObjectiveHash.Current != vars.latestObjectiveHash.Old) {
		print("vars.latestObjectiveHash Old " + ((IntPtr)vars.latestObjectiveHash.Old).ToString("X") + " - Current " + ((IntPtr)vars.latestObjectiveHash.Current).ToString("X"));
	}
}

exit
{
    timer.IsGameTimePaused = true;
}

start
{
    return vars.state.Current == 0xE89FFD52 && !vars.playerControlEnabled.Old && vars.playerControlEnabled.Current;
}

isLoading
{
    return vars.isLoading.Current || vars.state.Current == 0x469239DF || vars.state.Current == 0xD439EBF1 || vars.state.Current == 0xB5C73550 || vars.state.Current == 0x63C25A55 || vars.state.Current == 0;
}

shutdown
{
	game.Suspend();
	vars.FreeMemory(game);
	game.WriteBytes((IntPtr)vars.completeMissionFunctionAddress, (byte[])vars.originalMissionCompleteFunctionCode); //Restore original bytecode
	game.WriteBytes((IntPtr)vars.completeObjectiveFunctionAddress, (byte[])vars.originalObjectiveCompleteFunctionCode); //Restore original bytecode
	game.Resume();
}

split
{

	if (vars.latestObjectiveHash.Current != vars.latestObjectiveHash.Old)
	{
		if (!vars.autoEndNext && vars.latestObjectiveHash.Current == 0x1C34375B7D39C051 && vars.latestObjectiveHash.Old != 0 /*== 0x2A351C86227EC051*/) { //can't check for that because bureau alerts...
			print("catching autoEnd");
			vars.autoEndNext = true;
			refreshRate = 1; //HACKHACKHACK: i know this is really bad, but because we track the final cutscene with playerControlEnabled, which sometimes updates later than the objective, we need to wait a second so it doesn't split on the projector
			return false;
		}
	}

	if (vars.autoEndNext)
	{
		if (refreshRate == 1) {
			refreshRate = 60;
			return false;
		}

		if (vars.autoEndNext && !vars.playerControlEnabled.Current && vars.playerControlEnabled.Old) {
			print("triggering end split");
			vars.autoEndNext = false;
			game.WriteBytes((IntPtr)vars.latestObjectiveHashAddress, new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
			return true;
		}
		//return false;
	}

	if (vars.isMissionCompleted.Current && !vars.isMissionCompleted.Old)
	{
		game.WriteBytes((IntPtr)vars.isMissionCompletedAddress, new byte[] {0x00});
		//This whole RPM heavy part has to be done here rather than init as I witnessed some pointer changes during gameplay.
		//Some cache system could be implemented with a MemoryWatcher, but the following code should be fast enough on any computer able to run that game anyway.
	
		//Here we are looking into the global sm_instances pool to find the mission manager component, from which we will be able to get the list of all game missions
		var componentStateArray = game.ReadValue<IntPtr>(game.ReadValue<IntPtr>((IntPtr)vars.sm_instances + 8));
		while (game.ReadValue<int>(componentStateArray + 8) != 0x6871eafd) //This is some kind of checksum equal to "MissionManagerSingletonComponentState"
			componentStateArray += 24;
		var missionManagerSingletonComponentState = game.ReadValue<IntPtr>(componentStateArray + 16);
		var missionArrayOffset = game.ReadValue<int>(game.ReadValue<IntPtr>(missionManagerSingletonComponentState + 8) + 20);
		var missionArray = game.ReadValue<IntPtr>(missionManagerSingletonComponentState + missionArrayOffset + 88);
		var missionArraySize = game.ReadValue<int>(missionManagerSingletonComponentState + missionArrayOffset + 96);
		
		//Here we iterate into our mission array and try to match the mission globalID with the one we got from the mission completion hook
		var missionGID = game.ReadValue<int>((IntPtr)vars.isMissionCompletedAddress + 1);
		
		print("missionGID " + ((int)missionGID).ToString("X") + " - missionArraySize " + missionArraySize.ToString());
		if (missionGID == 0x529729E) { //special case for "Endgame" mission, to stop it from splitting on the credits
			return false;
		}

		int i = 0;
		while (game.ReadValue<int>(missionArray + 4) != missionGID) {
			if (i > missionArraySize) {
				print("Mission not found in missionArray (invalid or undefined), skipping");
				return false;
			}
			missionArray += 47 * 8;
			i++;
		}

		var triggerName = game.ReadString(missionArray + 0xC0, 15);
		if (triggerName == "OnAlertAppeared") {
			print("Bureau alert, skipping");
			return false;
		}
		return true;
	}
	else if (vars.isMissionCompleted.Current && vars.isMissionCompleted.Old) { //This happens at least once at the end of a run, because split isn't called (we end on dylan intercation) but mission still complete when getting back to bureau, our boolean will be stuck on true and break the autosplitter until game restart.
		game.WriteBytes((IntPtr)vars.isMissionCompletedAddress, new byte[] {0x00});
	}

	if (vars.latestObjectiveHash.Current != vars.latestObjectiveHash.Old)
	{

		if (settings["intro_subsplits"])
		{
			/*
			should check for the current mission gid?
			maybe it'd be a better idea to check against the old as well, incase this causes any random splits later
			could also probably check the expected inputEnabled state as well just to be totally safe
			*/

			switch ((UInt64)vars.latestObjectiveHash.Current)
			{ // maybe this should be checking against the old objectiveHash as well, incase this causes any random splits down the line....

				case 0x80C6DA414868051:		//Investigate the noise in the Director's Office (reaching office) MAYBE REMOVE THIS ONE
				case 0x29FECD336DD44051:	//Welcome to the Oldest House - Follow the Board's instructions to complete the Astral Plane Challenge (astral plane)
				case 0x10469758BD9F0051:	//Welcome to the Oldest House - Proceed Further Into the Bureau (leaving astral plane)
				case 0x3132CD8588D24051:	//Welcome to the Oldest House - Cleanse the Control Point
				//case 0x318295969DC70051:	//Welcome to the Oldest House - Speak with the voice on the Safe Room Intercom 
				//case 0x32330AEED172C051:	//Welcome to the Oldest House - Cleanse the Hiss-corrupted Agent
				case 0x3774770F0180051:		//Welcome to the Oldest House - Speak with Emily Pope
				//case 0x51DD0111FFB0051:		//Welcome to the Oldest House/Unknown Caller - Enter the Communications Dept. to find the Hotline
				case 0x367A9559D4A9C051:	//Unknown Caller - Navigate through the Communications Dept. (cleansed dead letters cp)
				//case 0x1E47AA743A050051:	//Unknown Caller - Reach the Object of Power to Cleanse it
				case 0x13607262FE258051:	//Unknown Caller - Use Launch to complete the Astral Plane challenge
				case 0x14D67242479FC051:	//Unknown Caller - Proceed through the Communications Dept.
				//everything below might be skippable in the future
				//case 0x3D50D4AC7F740051:	//Unknown Caller - Find the Hotline Object of Power
				case 0x35806926DF63C051:	//Unknown Caller - Traverse the Oceanview Motel
				case 0x16BDA8576AB68051:	//Unknown Caller - Pick up the Hotline
				//case 0xE8B59972B254051:		//Unknown Caller - Complete the Astral Plane Challenge
				case 0x21D1ECA6BEAA4051:	//Unknown Caller - Speak with Emily
				//case 0x2CA177693EB94051:	//Directorial Override - Find Ahti the janitor
				case 0x22F74A8FE8D0C051:	//Merry Chase - Use evade to complete the Astral Plane challenge
				//case 0x35CAA03DC7334051:	//Directorial Override - Find a way to fix the NSC Power Plant - skipped with slidey
				//case 0x152DB5CD65554051:	//Directorial Override - Speak with Emily
					return true;
				default:
				break;
			}
		}
	}

	return false;
}

/*
    Used state hashes (FNV-1a):
    0x469239DF = ClientStatePlatformServicesLogon
    0xD439EBF1 = ClientStateStart
    0xB5C73550 = ClientStateSplashScreen
    0x63C25A55 = ClientStateMainMenu
    0xE89FFD52 = ClientStateInGame
*/

/*
	Used/useful objective hashes
	0x3FDF050CEAC10051 //Polaris - Cleanse the siphons
	0xC31E52063870051 //Polaris - Reach Polaris (credits starting)
	0x1C34375B7D39C051 //Take Control - Turn off the Slide Projector (updated at Reach Dylan)
*/


