#include <iostream>

using namespace std;

string DecodeROT13(string text)
{
  string result = "";
  for (int i = 0; i < text.size(); i++)
  {
    if (isalpha(text[i]))
    {
      if (text[i] - 'a' < 14)
      {
        result += text[i] + 13;
      }
      else
      {
        result += text[i] - 13;
      }
    }
    else
    {
      result += text[i];
    }
  }
  return result;
}

int main()
{
  string message;
  cin >> message;
  cout << DecodeROT13(message);

  return 0;
}
