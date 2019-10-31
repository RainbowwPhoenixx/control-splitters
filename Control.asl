state("Control_DX11", "DX11") { }
state("Control_DX12", "DX12") { }

startup
{
    vars.gameTarget = new SigScanTarget(3,
        "48 8B 05 ????????",  // mov  rax, [Control_DX1#.exe+????????]
        "48 8B 48 30",        // mov  rcx, [rax+30]
        "80 B9 ???????? 00"); // cmp  byte ptr [rcx+?], 00

    vars.inputManagerTarget = new SigScanTarget(10, "48 89 86 18 01 00 00 48 89 35"); // signature to get InputManager instance pointer
}

init
{
    var module = modules.First();
    var inputStr = module.ModuleName == "Control_DX11.exe" ? "input_rmdwin7_f.dll" : "input_rmdwin10_f.dll";

    var scanner = new SignatureScanner(game, module.BaseAddress, module.ModuleMemorySize);
    var gameScan = scanner.Scan((SigScanTarget)vars.gameTarget);

    var inputModule = modules.Single(m => m.ModuleName == inputStr);
    var imScanner = new SignatureScanner(game, inputModule.BaseAddress, inputModule.ModuleMemorySize);
    var imScan = imScanner.Scan((SigScanTarget)vars.inputManagerTarget);

    if (imScan == IntPtr.Zero || gameScan == IntPtr.Zero)
    {
        throw new Exception("Scan failed!");
    }

    var offset = game.ReadValue<int>(gameScan);
    var imOffset = game.ReadValue<int>(imScan);
    var loadingOffset = game.ReadValue<int>(gameScan + 10);

    Thread.Sleep(2500); // Give the game a chance to initialize..

    // Boolean for loading
    vars.isLoading = new MemoryWatcher<bool>(new DeepPointer(module.ModuleName, (int)((long)(gameScan + offset + 4) - (long)module.BaseAddress), 0x30, loadingOffset));

    // ClientState hash
    vars.state = new MemoryWatcher<uint>(new DeepPointer(module.ModuleName, (int)((long)(gameScan + offset + 4) - (long)module.BaseAddress), 0x30, 0x1A8));

    // InputManager.playerInputEnabled
    vars.playerInputEnabled = new MemoryWatcher<bool>(new DeepPointer(inputModule.ModuleName, (int)((long)(imScan + imOffset + 4) - (long)inputModule.BaseAddress), 0x8D));
}

update
{
    vars.isLoading.Update(game);
    vars.state.Update(game);
    vars.playerInputEnabled.Update(game);
}

exit
{
    timer.IsGameTimePaused = true;
}

start
{
    return vars.state.Current == 0xE89FFD52 && !vars.playerInputEnabled.Old && vars.playerInputEnabled.Current;
}

isLoading
{
    return vars.isLoading.Current || vars.state.Current == 0x469239DF || vars.state.Current == 0xD439EBF1 || vars.state.Current == 0xB5C73550 || vars.state.Current == 0x63C25A55 || vars.state.Current == 0;
}

/*
    Used state hashes (FNV-1a):
    0x469239DF = ClientStatePlatformServicesLogon
    0xD439EBF1 = ClientStateStart
    0xB5C73550 = ClientStateSplashScreen
    0x63C25A55 = ClientStateMainMenu
    0xE89FFD52 = ClientStateInGame
*/
