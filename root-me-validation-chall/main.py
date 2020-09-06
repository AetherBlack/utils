#!/usr/bin/python3

from bs4 import BeautifulSoup

import requests
import time

#URL categorie
URL = ["https://www.root-me.org/fr/Challenges/App-Script/",
        "https://www.root-me.org/fr/Challenges/App-Systeme/",
        "https://www.root-me.org/fr/Challenges/Cracking/",
        "https://www.root-me.org/fr/Challenges/Cryptanalyse/",
        "https://www.root-me.org/fr/Challenges/Forensic/",
        "https://www.root-me.org/fr/Challenges/Programmation/",
        "https://www.root-me.org/fr/Challenges/Realiste/",
        "https://www.root-me.org/fr/Challenges/Reseau/",
        "https://www.root-me.org/fr/Challenges/Steganographie/",
        "https://www.root-me.org/fr/Challenges/Web-Client/",
        "https://www.root-me.org/fr/Challenges/Web-Serveur/"]

PROFIL_URL = "https://www.root-me.org/Black-Aether?inc=score&lang=fr"
#PROFIL_URL = "https://www.root-me.org/Keyzen-462235?inc=score&lang=fr"

def get_content(url_categorie):
    #Get the result
    res = requests.get(url_categorie)
    #Check the response of res
    while res.status_code != 200:
        #Sleep when Too Many Request
        time.sleep(5)
        #Then relaunch the requests
        res = requests.get(url_categorie)
    #Return the result
    return res

if __name__ == "__main__":
    #Contient les challenges et leur validation
    challenges = dict()
    #Pour chaque categorie
    for url_categorie in URL:
        #Get categorie name
        categorie = url_categorie.replace("https://www.root-me.org/fr/Challenges/", "").replace("/","")
        print(categorie)
        #Get the result of the page
        res = get_content(url_categorie)
        #parse the result with bs4
        soup = BeautifulSoup(res.text, "html.parser")
        #Get all tags <a></a>
        tags = soup.find_all("a")
        #For each lines get the challenge name and the number of validation
        for index in range(len(tags)):
            #If the line is the number of validation
            if "Qui a validé ?" in str(tags[index]):
                #Key challenge name - value number of validation
                name_challenge = categorie + "#####" + tags[index - 1].string
                nmb_validation = int(tags[index].string)
                challenges[name_challenge] = nmb_validation
                #print(name_challenge, nmb_validation)

    #Order the var
    classment = sorted(challenges.items(), key=lambda items: items[1])
    #Reverse the list
    classment.reverse()

    #Get challenge done
    challenge_done = list()
    challenge_not_done = list()
    #Get the page content
    res = get_content(PROFIL_URL)
    #bs4 the content
    soup = BeautifulSoup(res.text, "html.parser")
    #Get all line with <a> tag
    a_tags = soup.find_all("a")
    #Loop to add challenge to var
    challenges_user = list()
    for line in a_tags:
        if 'class="rouge"' in str(line) or 'class="vert"' in str(line):
            challenges_user.append(line)
    #Add challenge to the good list
    for chall in challenges_user:
        #Add not done challenge
        if 'class="rouge"' in str(chall):
            challenge_not_done.append(chall.string.replace(" x\xa0", ""))
        elif 'class="vert"' in str(chall):
            challenge_done.append(chall.string.replace(" o\xa0", ""))



    #Convert result into html page
    #Headers
    html_page = """<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@100;900&display=swap" rel="stylesheet"> 
                    <style>
                        table {
                            border-collapse: collapse;
                            margin: 0 auto;
                            width: 15vw;
                            table-layout: fixed;
                            width: 100%;
                        }
                        td, th {
                            border: 1px solid black;
                            text-align: center;
                            font-family: 'Noto Sans JP', sans-serif;
                        }
                        tr:hover {
                            background-color: chartreuse;
                        }
                        fieldset {
                            position: fixed;
                            top: 0;
                            left: 0;
                            margin-top: 20vw;
                            background-color: white;
                        }
                        .rouge {
                            background-color: red;
                        }
                        .vert {
                            background-color: green;
                        }
                    </style>
                    <script>
                        function filter(tag){
                            //Get the categorie name
                            var categorie = tag.dataset.categorie;
                            //Get all tr on the table
                            var row = document.getElementsByTagName("tr");
                            //loop
                            for (var i = 0; i < row.length; i++)
                            {
                                //Get the line
                                var field_categorie = row[i];
                                //Never delete title
                                if (field_categorie.dataset.categorie == "Title")
                                {
                                    continue;
                                }
                                //If the categorie clicked is the same as the line
                                if (field_categorie.dataset.categorie == categorie)
                                {
                                    //Check if the line is already not display
                                    if (field_categorie.style.display == "none")
                                    {
                                        //Then show them
                                        field_categorie.style.display = "";
                                    }
                                    else
                                    {
                                        //Else hidden them
                                        field_categorie.style.display = "none";
                                    }
                                }
                            }
                        }
                    </script>
                    <table>
                        <tr data-categorie='Title'>
                            <th>
                                Categorie
                            </th>
                            <th>
                                Challenge name
                            </th>
                            <th>
                                Validations
                            </th>
                        </tr>
                """
    #Content
    for challenge in classment:
        #Get the categorie
        categorie = challenge[0].split("#####")[0]
        #Get the challenge name
        challenge_name = challenge[0].split("#####")[1]
        #Get the nbr of validations
        nbr_validation = challenge[1]
        #Check if the challenge is done
        if challenge_name in challenge_done:
            color = "vert"
        elif challenge_name in challenge_not_done:
            color = "rouge"
        else:
            color = ""
        #Add to the var
        html_page += """<tr data-categorie='{0}' class='{3}'>
                            <td>
                                {0}
                            </td>
                            <td>
                                {1}
                            </td>
                            <td>
                                {2}
                            </td>
                        </tr>
                    """.format(categorie, challenge_name, nbr_validation, color)
    #Bottom
    html_page += """<fieldset>
                        <ul>
                            <li>
                                <input type="checkbox" onclick="filter(this);" data-categorie="App-Script" checked>App-Script</button>
                            </li>
                            <li>
                                <input type="checkbox" onclick="filter(this);" data-categorie="App-Systeme" checked>App-Systeme</button>
                            </li>
                            <li>
                                <input type="checkbox" onclick="filter(this);" data-categorie="Cracking" checked>Cracking</button>
                            </li>
                            <li>
                                <input type="checkbox" onclick="filter(this);" data-categorie="Cryptanalyse" checked>Cryptanalyse</button>
                            </li>
                            <li>
                                <input type="checkbox" onclick="filter(this);" data-categorie="Forensic" checked>Forensic</button>
                            </li>
                            <li>
                                <input type="checkbox" onclick="filter(this);" data-categorie="Programmation" checked>Programmation</button>
                            </li>
                            <li>
                                <input type="checkbox" onclick="filter(this);" data-categorie="Realiste" checked>Realiste</button>
                            </li>
                            <li>
                                <input type="checkbox" onclick="filter(this);" data-categorie="Reseau" checked>Reseau</button>
                            </li>
                            <li>
                                <input type="checkbox" onclick="filter(this);" data-categorie="Steganographie" checked>Steganographie</button>
                            </li>
                            <li>
                                <input type="checkbox" onclick="filter(this);" data-categorie="Web-Client" checked>Web-Client</button>
                            </li>
                            <li>
                                <input type="checkbox" onclick="filter(this);" data-categorie="Web-Serveur" checked>Web-Serveur</button>
                            </li>
                        </ul>
                    </fieldset>
                    </table>"""

    #Write into file
    with open("result.html", "w") as f:
        f.write(html_page) 
