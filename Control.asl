state("Control_DX11", "DX11") { }
state("Control_DX12", "DX12") { }

// Open Control before LiveSplit

init
{
    var scanner = new SignatureScanner(game, modules.First().BaseAddress, modules.First().ModuleMemorySize);
    var gameScan = scanner.Scan(new SigScanTarget(3,
        "48 8B 05 ????????",   // mov  rax, [Control_DX1#.exe+????????]
        "48 8B 48 30",         // mov  rcx, [rax+30]
        "80 B9 93030000 00")); // cmp  byte ptr [rcx+393], 00

    if (gameScan == IntPtr.Zero)
    {
        throw new Exception("Scan failed!");
    }

    var offset = game.ReadValue<int>(gameScan);
    vars.isLoading = new MemoryWatcher<bool>(new DeepPointer(modules.First().ModuleName, (int)((long)(gameScan + offset + 4) - (long)modules.First().BaseAddress), 0x30, 0x393));
}

update
{
    vars.isLoading.Update(game);
}

isLoading
{
    return vars.isLoading.Current;
}
