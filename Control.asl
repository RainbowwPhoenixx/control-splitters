state("Control_DX11", "DX11") { }
state("Control_DX12", "DX12") { }

startup
{
    vars.gameClosed = false;
}

init
{
    var scanner = new SignatureScanner(game, modules.First().BaseAddress, modules.First().ModuleMemorySize);
    var gameScan = scanner.Scan(new SigScanTarget(3,
        "48 8B 05 ????????",   // mov  rax, [Control_DX1#.exe+????????]
        "48 8B 48 30",         // mov  rcx, [rax+30]
        "80 B9 ???????? 00")); // cmp  byte ptr [rcx+?], 00

    if (gameScan == IntPtr.Zero)
    {
        throw new Exception("Scan failed!");
    }

    Thread.Sleep(2500); // Give the game a chance to initialize..

    var offset = game.ReadValue<int>(gameScan);
    var loadingOffset = game.ReadValue<short>(gameScan + 10);

    vars.isLoading = new MemoryWatcher<bool>(new DeepPointer(modules.First().ModuleName, (int)((long)(gameScan + offset + 4) - (long)modules.First().BaseAddress), 0x30, loadingOffset));
    vars.state = new MemoryWatcher<uint>(new DeepPointer(modules.First().ModuleName, (int)((long)(gameScan + offset + 4) - (long)modules.First().BaseAddress), 0x30, 0x1A8));

    if (vars.gameClosed)
    {
        timer.IsGameTimePaused = false;
    }
}

exit
{
    timer.IsGameTimePaused = true;
    vars.gameClosed = true;
}

update
{
    vars.isLoading.Update(game);
    vars.state.Update(game);
}

isLoading
{
    return vars.isLoading.Current || vars.state.Current = 0x469239DF || vars.state.Current == 0xD439EBF1 || vars.state.Current == 0xB5C73550 || vars.state.Current == 0x63C25A55 || vars.state.Current == 0;
}

/*
    Used state hashes (FNV-1a):
    0x469239DF = ClientStatePlatformServicesLogon
    0xD439EBF1 = ClientStateStart
    0xB5C73550 = ClientStateSplashScreen
    0x63C25A55 = ClientStateMainMenu
*/
