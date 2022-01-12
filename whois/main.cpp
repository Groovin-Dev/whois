#include <iostream>
#include <cstring>

#include "whois.h"

using namespace std;

/**
 * WHOIS 
 *
 * WHOIS is a TUI that allows users to search LDAP using provided authentication
 * It supports the following commands:
 * help
 * search [query]
 * info (Only works if search was successful)
 * remote (Only works if search was successful)
 * quit
 */

void print_ascii_art()
{
	// Print the ascii art
	cout << " ▄     ▄ ▄▄   ▄▄ ▄▄▄▄▄▄▄ ▄▄▄ ▄▄▄▄▄▄▄\n";
	cout << "█ █ ▄ █ █  █ █  █       █   █       █\n";
	cout << "█ ██ ██ █  █▄█  █   ▄   █   █  ▄▄▄▄▄█\n";
	cout << "█       █       █  █ █  █   █ █▄▄▄▄▄\n";
	cout << "█       █   ▄   █  █▄█  █   █▄▄▄▄▄  █\n";
	cout << "█   ▄   █  █ █  █       █   █▄▄▄▄▄█ █\n";
	cout << "█▄▄█ █▄▄█▄▄█ █▄▄█▄▄▄▄▄▄█▄▄▄█▄▄▄▄▄▄▄█\n";

	// Print the version
	cout << "Version: 2.0.0\n";

	// Print the author
	cout << "Author: Groovin-Dev\n";

	// Print a new line
	cout << "\n";
}

void print_help()
{
	// This will print all the available commands
	cout << "Available commands:\n";
	cout << "help\n";
	cout << "search [query]\n";
	cout << "info\n";
	cout << "remote\n";
	cout << "quit\n";
}

// The main function takes arguments from the command line
int main()
{
	// Print the ascii art
	print_ascii_art();

	// Define an empty user object to serve as the last user
	User user{};

	// Create a new whois class
	whois wis;

	// Create an enum to store the commands
	enum Commands
	{
		HELP,
		SEARCH,
		INFO,
		REMOTE,
		QUIT
	};

	// Create a map of commands
	map<string, Commands> commands = {
		{"help", HELP},
		{"search", SEARCH},
		{"info", INFO},
		{"remote", REMOTE},
		{"quit", QUIT}};

	// Auth and bind the user
	wis.auth();

	// Start the main loop
	while (true)
	{
		// The prompt will either be > or (samaccountname) >
		// The username will reflect the latest successful search
		// Create a new string to hold the prompt
		string prompt_string;

		// Check if the users samaccountname is set
		if (user.samaccountname != nullptr)
		{
			// Set the prompt to (samaccountname) >
			prompt_string = string(user.samaccountname) + " > ";
		}
		else
		{
			// Set the prompt to >
			prompt_string = "> ";
		}

		// Print the prompt
		cout << prompt_string;

		// Get the user input
		char input[100];
		cin.getline(input, 100);

		// Split the input into an array of strings and count the amount of args
		char *args[100];
		int argc = 0;
		char *token = strtok(input, " ");
		while (token != NULL)
		{
			args[argc] = token;
			argc++;
			token = strtok(NULL, " ");
		}

		// The first argument is the command
		char *command = args[0];

		// Subtract 1 from argc to get the amount of args
		argc--;

		// After the command, all other args are arguments
		// Remove the first argument from the array
		for (int i = 0; i < argc; i++)
		{
			args[i] = args[i + 1];
		}

		// Switch on the command using the map
		switch (commands[command])
		{
		case HELP:
			// Print the help. If there is an argument, print the help for that command
			if (argc == 0)
			{
				print_help();
			}
			else
			{
				wis.help(args[0]);
			}
			break;
		case SEARCH:
			// Search the LDAP
			// Join all the arguments into a single string with spaces
			char query[100];
			strcpy(query, "");
			for (int i = 0; i < argc; i++)
			{
				strcat(query, args[i]);
				strcat(query, " ");
			}

			// Remove the last space
			query[strlen(query) - 1] = '\0';

			// Search the LDAP
			wis.search(query);

			break;
		case INFO:
			// Print the user information
			wis.info();
			break;
		case REMOTE:
			// Remote into the users computer
			wis.remote();
			break;
		case QUIT:
			// Quit the program
			wis.quit();
			return 0;
		default:
			// Print the help
			print_help();
			break;
		}
	}

	// Return 0
	return 0;
}
