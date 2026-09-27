state("CONTROLResonant", "1.3.3") //day 1 patch, exe version is 0.563.737.9
{
	int state : 0x5A18C30;
}

state("CONTROLResonant", "1.3.2") //exe version is 0.563.540.8
{
	int state : 0x5B0EC30;
}

init
{
	switch (modules.First().ModuleMemorySize)
	{
		case 103813120:
			version = "1.3.3";
			break;
		case 104820736:
			version = "1.3.2";
			break;
		default:
			print("ModuleMemorySize: " + modules.First().ModuleMemorySize.ToString());
			break;
	}
}

startup
{
}

update
{
	//print(current.state.ToString());
}

start
{
	return (current.state == 3 && old.state == 2);
}

split
{
	if (current.state != old.state) {
		if (current.state == 19) {
			return (old.state && old.state != 1); //split on credits to end for now
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
		case 18: //fast travel
		case 15: //main menu after credits
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
		18: fast travel
		15: main menu after credits?
		19: credits
*/
