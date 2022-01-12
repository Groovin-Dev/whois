#ifndef WHOIS_WHOIS_H
#define WHOIS_WHOIS_H

#include <windows.h>
#include <winldap.h>
#include <string>
#include <map>
#include <iostream>
#include <vector>

using namespace std;

// This is the User struct to store search results
// This will have almost all the information from LDAP that we can get
struct User
{
	const char *cn;				// The common name
	const char *department;		// The department
	const char *description;	// The description
	const char *employeeid;		// The employee ID
	const char *email;			// The users email
	const char *name;			// The full name
	const char *samaccountname; // The users account name
	const char *title;			// The users title
};

// The command struct to be a shell
struct Command
{
	// The name of the command
	const char *name;

	// The help text for the command
	const char *help;
};

// This class will store all the command functions
class whois
{
private:
	// -----
	// Store some variables
	// -----
	const char *host = "HOST_HERE";
	ULONG port = 389;
	const char *base = "BASE_HERE";

	// Store the latest LDAP entry for raw access
	LDAPMessage *entry;

	// Store the current user
	User user;

	// Create a new commands map
	map<string, Command> commands = {
		{"help", {"help", "Get help on a command"}},
		{"search", {"search <query>", "Search for a user"}},
		{"info", {"info", "Get the current users info"}},
		{"remote", {"remote", "Remote into the current users computer"}},
		{"quit", {"quit", "Quit the program"}}};

	// Store the ldap session
	LDAP *ldap;

public:
	// -----
	// User Functions
	// -----

	// Set the user
	void setUser(User user);
	// Get the user
	User getUser();

	// -----
	// Command Functions
	// -----
	// Print help about all commands or a specific command
	void help(string command);
	// Auth to LDAP
	LDAP *auth();
	// Search with a provided query
	void search(string query);
	// Get the user's information
	void info();
	// Remote into the users computer
	void remote();
	// Close the program
	void quit();
};

#endif //WHOIS_WHOIS_H
