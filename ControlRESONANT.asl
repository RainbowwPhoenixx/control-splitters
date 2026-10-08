state("CONTROLResonant", "1.4.2") //2026-10-8 hotfix, exe version 0.564.629.5, exe size 103813120
{
	int state : 0x5A0CC90;
}

state("CONTROLResonant", "1.4.1") //2026-10-2 hotfix, exe version 0.564.478.0, exe size 104734720
{
	int state : 0x5AEDC90;
}

state("CONTROLResonant", "1.4.0") //2026-10-01 update, exe version 0.564.208.5, exe size 104701952
{
	int state : 0x5AE5C90;
}

state("CONTROLResonant", "1.3.3") //day 1 patch, exe version is 0.563.737.9, exe size 103813120
{
	int state : 0x5A18C30;
}

state("CONTROLResonant", "1.3.2") //exe version is 0.563.540.8, exe size 104820736
{
	int state : 0x5B0EC30;
}

init
{
	var module = modules.First();
	var versionInfo = module.FileVersionInfo;
	switch (versionInfo.FileVersion)
	{
		case "0.564.629.5":	version = "1.4.2";	break;
		case "0.564.478.0":	version = "1.4.1";	break;
		case "0.564.208.5":	version = "1.4.0";	break;
		case "0.563.737.9":	version = "1.3.3";	break;
		case "0.563.540.8":	version = "1.3.2";	break;
		default:
			print("UNKNOWN VERSION: " + "FileVersion: " + versionInfo.FileVersion.ToString() + " - ModuleMemorySize: " + module.ModuleMemorySize.ToString());
			break;
	}
}

startup
{
}

update
{
	if (current.state != old.state) {
		print("current state: " + current.state.ToString());
	}
}

start
{
	return (current.state == 3 && old.state == 2);
}

split
{
	if (current.state != old.state) {
		if (current.state == 19) {
			return (old.state != 0 && old.state != 1); //split on credits to end for now
		}
	}
	return false;
}

isLoading
{
	switch ((Int64)current.state)
	{
		case 0: //intro splash
		case 1: //main menu
		case 2: //loading from main menu
		case 10: //title splash
		case 11: //loading to menu
		//case 15: //main menu after credits
		case 18: //fast travel
		case 19: //credits
			return true;
	}
	return false;
}

exit
{
	timer.IsGameTimePaused = true;
}

/*
	states
		0: null state / intro splash screens
		1: main menu screen
		2: loading from main menu
		3: ingame
		5: in-game menu
		10: photo-sensitivity warning/autosave message/title splash screen
		11: loading to menu
		15: main menu after credits?
		18: fast travel
		19: credits
*/
