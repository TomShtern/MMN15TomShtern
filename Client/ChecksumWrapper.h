#pragma once
class ChecksumWrapper
{
	#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <string>
#include <vector>

class Checksum {
public:
    Checksum();
    ~Checksum();

    void update(const std::string& data);
    void update(const std::vector<unsigned char>& data);
    std::string getChecksum();

private:
    // Private member variables and functions
    // ...
};

#endif // CHECKSUM_H

public:
	ChecksumWrapper();
	~ChecksumWrapper();

	void update(const std::string& data);
	void update(const std::vector<unsigned char>& data);
	std::string getChecksum();
};

//Name: Tom Shtern; ID: 318783289
//State: spaghetti code Not Finale, Did Not Finish In Time.............................................