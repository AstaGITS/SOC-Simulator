# SOC Simulator 2/5 - Vol de secret 1

```
Après l’action vue dans la partie 1, l’attaquant vole les identifiants système en mémoire. Retrouver le GUID du processus effectuant ce vol et le nom du fichier où il écrit les secrets volés.

Format du flag (insensible à la casse) : FCSC{6ccf8905-a033-4edc-8ed7-0a4b0a411e15|C:\Windows\Users\toto\Desktop\fichier.pdf}
```

L’analyse se concentre désormais sur les événements précédant le timestamp associé au vecteur initial de l'attaque et l’objectif est d’identifier un processus potentiellement lancé par l’attaquant.

La machine ciblée étant connue (exchange.tinfa.loc), sur TimelineExplorer nous appliquons un filtre spécifique pour affiner la recherche sur les événements liés à cette hôte et impliquant des lignes de commande :

`[Computer] = 'exchange.tinfa.loc' AND Contains([Details], 'Cmdline')`

Ce qui nous permet de visualiser rapidement les évènements ci-dessous : 

![evenements_timelineExplorer](evenements_timelineExplorer.png)

En examinant les titres des règles :

- “Suspicious System User Process Creation”
- “Potentially Suspicious PowerShell Child Processes”
- “Process Memory Dump Via Comsvcs.DLL”
- “Suspicious SYSTEM User Process Creation”

Nous allons donc nous renseigner sur (Comsvcs.DLL)[https://lolbas-project.github.io/lolbas/Libraries/comsvcs/].

![comsvcsdll_description](comsvcsdll_description.png)

L’utilisation de Comsvcs.DLL est effectivement suspecte : cette DLL est connue pour permettre le dump de la mémoire du processus lsass.exe, une méthode classique utilisée par les attaquants pour extraire des identifiants en clair depuis la mémoire.

L’événement analysé confirme cette activité. Dans les détails de l'évènement, on observe notamment :

`Cmdline: "C:\Windows\system32\rundll32.exe" C:\Windows\System32\comsvcs.dll MiniDump 652 attr.exe full ¦ Proc: C:\Windows\System32\rundll32.exe ¦ User: NT AUTHORITY\SYSTEM ¦ ParentCmdline: powershell ¦ LID: 0x3e7 ¦ LGUID: {b99a131f-8de7-62c2-e703-000000000000} ¦ PID: 17400 ¦ PGUID: {b99a131f-0d4b-62c3-ce03-00000000db01} ¦ ParentPID: 4688 ¦ ParentPGUID: {b99a131f-0ca8-62c3-c903-00000000db01} ¦ Description: Windows host process (Rundll32) ¦ Product: Microsoft® Windows® Operating System ¦ Company: Microsoft Corporation ¦ Hashes: SHA1=A40886F98905F3D9DBDD61DA1D59CCB4F4854758,MD5=80F8E0C26028E83F1EF371D7B44DE3DF,SHA256=9F1E56A3BF293AC536CF4B8DAD57040797D62DBB0CA19C4ED9683B5565549481,IMPHASH=F27A7FC3A53E74F45BE370131953896A`

À partir des données collectées, nous avons extrait le GUID associé à l’exécution suspecte :
{b99a131f-0d4b-62c3-ce03-00000000db01}.
Nous savons également que le fichier de sortie généré est nommé attr.exe.

Cependant, aucune mention explicite de son chemin d’accès n’a été trouvée dans les fichiers CSV précédemment générés, malgré des recherches ciblées sur le nom du binaire.

Face à cette impasse, une approche alternative consiste à utiliser ripgrep + strings pour effectuer une recherche en texte brut dans les fichiers .evtx, à la recherche de toute occurrence de attr.exe.

```
rg -i "attr.exe" --binary -E UTF-16 ./
./20220704T175527.evtx: binary file matches (found "\0" byte around offset 10)
strings -el ./20220704T175527.evtx | grep -C 5 "attr.exe"
C:\Windows\System32\inetsrv\
```

Nous pouvons également à l’aide d’un visualiseur d’événements Windows localiser précisément le chemin d'exécution du binaire. En filtrant sur l’Event ID 1 et en prenant comme référence l’horaire de l’événement en UTC+2 affiché dans TimelineExplorer, nous obtenons ce que l’on cherche.

![image_évènement_windows](image_évènement_windows.png)

C:\Windows\System32\inetsrv\ est donc le répertoire courant.

Flag : FCSC{b99a131f-0d4b-62c3-ce03-00000000db01|C:\Windows\System32\inetsrv\attr.exe}

