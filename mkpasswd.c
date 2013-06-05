/*
 *    Copyright (c) 2013 Michael Sierchio
 *    
 *    All rights reserved.
 *    
 *    Redistribution and use in source and binary forms, with or
 *    without modification, are permitted provided that the
 *    following conditions are met:
 *    
 *    1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer.
 *    
 *    2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *    
 *    THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS
 *    IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 *    FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT
 *    SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *    INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *    OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 *    THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 *    OF SUCH DAMAGE.
 */


/*
 *  mkpasswd:   a passphrase generator
 *
 *          To compile:    cc -O0 -o mkpasswd mkpasswd.c
 *    
 *          mkpasswd was inspired by the babble strings produced
 *          by the original Bellcore S/Key OTP generator - however,
 *          its purpose is merely to produce passwords with a promise
 *          of 66 bits of entropy (in the default configuration).
 *          The dictionary differs from the original in that only
 *          3- and 4-letter words are used.  The security of the
 *          passphrases generated is reducible to the security of
 *          the underlying system RNG (e.g., /dev/random). Six words
 *          are selected at random from a dictionary of 2048 words,
 *          yielding 2^66 possible passphrases.
 *    
 *          To make passphrases more legible, the -s option inserts
 *          spaces, and the -d option inserts dashes.  It is up to
 *          the user whether to include these.
 *    
 *          Since the common Linux implementation of /dev/random
 *          blocks, a conditional compile for Linux has the program
 *          use /dev/urandom.  This may reduce the security of
 *          passwords.  On FreeBSD and OS X /dev/random is of a
 *          different design, using a 256-bit variant of Yarrow
 *          when no hardware RNG is present, with support for
 *          hardware RNGs if available.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>


#define WORDS_PER_PHRASE	6
#ifdef __linux__
#define	RANDDEV	"/dev/urandom"
#else
#define	RANDDEV	"/dev/random"
#endif


static char words[2048][5] = {
    "Abe",  "Abed", "Abel", "Abet", "Able", "Abut", "Ace",  "Ache",
    "Acid", "Acme", "Acre", "Act",  "Acta", "Acts", "Ada",  "Adam",
    "Add",  "Adds", "Aden", "Afar", "Afro", "Age",  "Agee", "Ago",
    "Ahem", "Ahoy", "Aid",  "Aida", "Aide", "Aids", "Aim",  "Air",
    "Airy", "Ajar", "Akin", "Alan", "Alec", "Alga", "Alia", "All",
    "Ally", "Alma", "Aloe", "Alp",  "Also", "Alto", "Alum", "Alva",
    "Amen", "Ames", "Amid", "Ammo", "Amok", "Amos", "Amra", "Amy",
    "Ana",  "And",  "Andy", "Anew", "Ann",  "Anna", "Anne", "Ant",
    "Ante", "Anti", "Any",  "Ape",  "Aps",  "Apt",  "Aqua", "Arab",
    "Arc",  "Arch", "Are",  "Area", "Argo", "Arid", "Ark",  "Arm",
    "Army", "Art",  "Arts", "Arty", "Ash",  "Asia", "Ask",  "Asks",
    "Ate",  "Atom", "Aug",  "Auk",  "Aunt", "Aura", "Auto", "Ave",
    "Aver", "Avid", "Avis", "Avon", "Avow", "Away", "Awe",  "Awk",
    "Awl",  "Awn",  "Awry", "Aye",  "Babe", "Baby", "Bach", "Back",
    "Bad",  "Bade", "Bag",  "Bah",  "Bail", "Bait", "Bake", "Bald",
    "Bale", "Bali", "Balk", "Ball", "Balm", "Bam",  "Ban",  "Band",
    "Bane", "Bang", "Bank", "Bar",  "Barb", "Bard", "Bare", "Bark",
    "Barn", "Barr", "Base", "Bash", "Bask", "Bass", "Bat",  "Bate",
    "Bath", "Bawd", "Bawl", "Bay",  "Bead", "Beak", "Beam", "Bean",
    "Bear", "Beat", "Beau", "Beck", "Bed",  "Bee",  "Beef", "Been",
    "Beer", "Beet", "Beg",  "Bela", "Bell", "Belt", "Ben",  "Bend",
    "Bent", "Berg", "Bern", "Bert", "Bess", "Best", "Bet",  "Beta",
    "Beth", "Bey",  "Bhoy", "Bias", "Bib",  "Bid",  "Bide", "Bien",
    "Big",  "Bile", "Bilk", "Bill", "Bin",  "Bind", "Bing", "Bird",
    "Bit",  "Bite", "Bits", "Blab", "Blat", "Bled", "Blew", "Blob",
    "Bloc", "Blot", "Blow", "Blue", "Blum", "Blur", "Boar", "Boat",
    "Bob",  "Boca", "Bock", "Bode", "Body", "Bog",  "Bogy", "Bohr",
    "Boil", "Bold", "Bolo", "Bolt", "Bomb", "Bon",  "Bona", "Bond",
    "Bone", "Bong", "Bonn", "Bony", "Boo",  "Book", "Boom", "Boon",
    "Boot", "Bop",  "Bore", "Borg", "Born", "Bose", "Boss", "Both",
    "Bout", "Bow",  "Bowl", "Box",  "Boy",  "Boyd", "Brad", "Brae",
    "Brag", "Bran", "Bray", "Bred", "Brew", "Brig", "Brim", "Brow",
    "Bub",  "Buck", "Bud",  "Budd", "Buff", "Bug",  "Bulb", "Bulk",
    "Bull", "Bum",  "Bun",  "Bunk", "Bunt", "Buoy", "Burg", "Burl",
    "Burn", "Burr", "Burt", "Bury", "Bus",  "Bush", "Buss", "Bust",
    "Busy", "But",  "Buy",  "Bye",  "Byte", "Cab",  "Cady", "Cafe",
    "Cage", "Cain", "Cake", "Cal",  "Calf", "Call", "Calm", "Cam",
    "Came", "Can",  "Cane", "Cant", "Cap",  "Car",  "Card", "Care",
    "Carl", "Carr", "Cart", "Case", "Cash", "Cask", "Cast", "Cat",
    "Cave", "Caw",  "Ceil", "Cell", "Cent", "Cern", "Chad", "Char",
    "Chat", "Chaw", "Chef", "Chen", "Chew", "Chic", "Chin", "Chou",
    "Chow", "Chub", "Chug", "Chum", "Cite", "City", "Clad", "Clam",
    "Clan", "Claw", "Clay", "Clod", "Clog", "Clot", "Club", "Clue",
    "Coal", "Coat", "Coca", "Cock", "Coco", "Cod",  "Coda", "Code",
    "Cody", "Coed", "Cog",  "Coil", "Coin", "Coke", "Col",  "Cola",
    "Cold", "Colt", "Coma", "Comb", "Come", "Con",  "Coo",  "Cook",
    "Cool", "Coon", "Coot", "Cop",  "Cord", "Core", "Cork", "Corn",
    "Cost", "Cot",  "Cove", "Cow",  "Cowl", "Coy",  "Crab", "Crag",
    "Cram", "Cray", "Crew", "Crib", "Crow", "Crud", "Cry",  "Cub",
    "Cuba", "Cube", "Cue",  "Cuff", "Cull", "Cult", "Cuny", "Cup",
    "Cur",  "Curb", "Curd", "Cure", "Curl", "Curt", "Cut",  "Cuts",
    "Dab",  "Dad",  "Dade", "Dale", "Dam",  "Dame", "Dan",  "Dana",
    "Dane", "Dang", "Dank", "Dar",  "Dare", "Dark", "Darn", "Dart",
    "Dash", "Data", "Date", "Dave", "Davy", "Dawn", "Day",  "Days",
    "Dead", "Deaf", "Deal", "Dean", "Dear", "Debt", "Deck", "Dee",
    "Deed", "Deem", "Deep", "Deer", "Deft", "Defy", "Del",  "Dell",
    "Den",  "Dent", "Deny", "Des",  "Desk", "Dew",  "Dial", "Dice",
    "Did",  "Die",  "Died", "Diet", "Dig",  "Dime", "Din",  "Dine",
    "Ding", "Dint", "Dip",  "Dire", "Dirt", "Disc", "Dish", "Disk",
    "Dive", "Dock", "Doe",  "Does", "Dog",  "Dole", "Doll", "Dolt",
    "Dome", "Don",  "Done", "Doom", "Door", "Dora", "Dose", "Dot",
    "Dote", "Doug", "Dour", "Dove", "Dow",  "Down", "Drab", "Drag",
    "Dram", "Draw", "Drew", "Drop", "Drub", "Drug", "Drum", "Dry",
    "Dual", "Dub",  "Duck", "Duct", "Dud",  "Due",  "Duel", "Duet",
    "Dug",  "Duke", "Dull", "Dumb", "Dun",  "Dune", "Dunk", "Dusk",
    "Dust", "Duty", "Each", "Ear",  "Earl", "Earn", "Ease", "East",
    "Easy", "Eat",  "Eben", "Echo", "Eddy", "Eden", "Edge", "Edgy",
    "Edit", "Edna", "Eel",  "Egan", "Egg",  "Ego",  "Elan", "Elba",
    "Eli",  "Elk",  "Ella", "Elm",  "Else", "Ely",  "Emil", "Emit",
    "Emma", "End",  "Ends", "Eric", "Eros", "Est",  "Etc",  "Eva",
    "Eve",  "Even", "Ever", "Evil", "Ewe",  "Eye",  "Eyed", "Face",
    "Fact", "Fad",  "Fade", "Fail", "Fain", "Fair", "Fake", "Fall",
    "Fame", "Fan",  "Fang", "Far",  "Farm", "Fast", "Fat",  "Fate",
    "Fawn", "Fay",  "Fear", "Feat", "Fed",  "Fee",  "Feed", "Feel",
    "Feet", "Fell", "Felt", "Fend", "Fern", "Fest", "Feud", "Few",
    "Fib",  "Fief", "Fig",  "Figs", "File", "Fill", "Film", "Fin",
    "Find", "Fine", "Fink", "Fir",  "Fire", "Firm", "Fish", "Fisk",
    "Fist", "Fit",  "Fits", "Five", "Fix",  "Flag", "Flak", "Flam",
    "Flat", "Flaw", "Flea", "Fled", "Flew", "Flit", "Flo",  "Floc",
    "Flog", "Flow", "Flub", "Flue", "Fly",  "Foal", "Foam", "Foe",
    "Fog",  "Fogy", "Foil", "Fold", "Folk", "Fond", "Font", "Food",
    "Fool", "Foot", "For",  "Ford", "Fore", "Fork", "Form", "Fort",
    "Foss", "Foul", "Four", "Fowl", "Fox",  "Frau", "Fray", "Fred",
    "Free", "Fret", "Frey", "Frog", "From", "Fry",  "Fuel", "Full",
    "Fum",  "Fume", "Fun",  "Fund", "Funk", "Fur",  "Fury", "Fuse",
    "Fuss", "Gab",  "Gad",  "Gaff", "Gag",  "Gage", "Gail", "Gain",
    "Gait", "Gal",  "Gala", "Gale", "Gall", "Galt", "Gam",  "Game",
    "Gang", "Gap",  "Garb", "Gary", "Gas",  "Gash", "Gate", "Gaul",
    "Gaur", "Gave", "Gawk", "Gay",  "Gear", "Gee",  "Gel",  "Geld",
    "Gem",  "Gene", "Gent", "Germ", "Get",  "Gets", "Gibe", "Gift",
    "Gig",  "Gil",  "Gild", "Gill", "Gilt", "Gin",  "Gina", "Gird",
    "Girl", "Gist", "Give", "Glad", "Glee", "Glen", "Glib", "Glob",
    "Glom", "Glow", "Glue", "Glum", "Glut", "Goad", "Goal", "Goat",
    "God",  "Goer", "Goes", "Gold", "Golf", "Gone", "Gong", "Good",
    "Goof", "Gore", "Gory", "Gosh", "Got",  "Gout", "Gown", "Grab",
    "Grad", "Gray", "Greg", "Grew", "Grey", "Grid", "Grim", "Grin",
    "Grit", "Grow", "Grub", "Gulf", "Gull", "Gum",  "Gun",  "Gunk",
    "Guru", "Gus",  "Gush", "Gust", "Gut",  "Guy",  "Gwen", "Gwyn",
    "Gym",  "Gyp",  "Haag", "Haas", "Hack", "Had",  "Hail", "Hair",
    "Hal",  "Hale", "Half", "Hall", "Halo", "Halt", "Ham",  "Han",
    "Hand", "Hang", "Hank", "Hans", "Hap",  "Hard", "Hark", "Harm",
    "Hart", "Has",  "Hash", "Hast", "Hat",  "Hate", "Hath", "Haul",
    "Have", "Haw",  "Hawk", "Hay",  "Hays", "Head", "Heal", "Hear",
    "Heat", "Hebe", "Heck", "Heed", "Heel", "Heft", "Held", "Hell",
    "Helm", "Help", "Hem",  "Hen",  "Her",  "Herb", "Herd", "Here",
    "Hero", "Hers", "Hess", "Hew",  "Hewn", "Hey",  "Hick", "Hid",
    "Hide", "High", "Hike", "Hill", "Hilt", "Him",  "Hind", "Hint",
    "Hip",  "Hire", "His",  "Hiss", "Hit",  "Hive", "Hob",  "Hobo",
    "Hoc",  "Hock", "Hoe",  "Hoff", "Hog",  "Hold", "Hole", "Holm",
    "Holt", "Home", "Hone", "Honk", "Hood", "Hoof", "Hook", "Hoot",
    "Hop",  "Hope", "Horn", "Hose", "Host", "Hot",  "Hour", "Hove",
    "How",  "Howe", "Howl", "Hoyt", "Hub",  "Huck", "Hue",  "Hued",
    "Huff", "Hug",  "Huge", "Hugh", "Hugo", "Huh",  "Hulk", "Hull",
    "Hum",  "Hunk", "Hunt", "Hurd", "Hurl", "Hurt", "Hush", "Hut",
    "Hyde", "Hymn", "Ibis", "Ice",  "Icon", "Icy",  "Ida",  "Idea",
    "Idle", "Iffy", "Ike",  "Ill",  "Inca", "Inch", "Ink",  "Inn",
    "Into", "Ion",  "Ions", "Iota", "Iowa", "Ira",  "Ire",  "Iris",
    "Irk",  "Irma", "Iron", "Isle", "Itch", "Item", "Its",  "Ivan",
    "Ivy",  "Jab",  "Jack", "Jade", "Jag",  "Jail", "Jake", "Jam",
    "Jan",  "Jane", "Jar",  "Java", "Jaw",  "Jay",  "Jean", "Jeff",
    "Jerk", "Jess", "Jest", "Jet",  "Jibe", "Jig",  "Jill", "Jilt",
    "Jim",  "Jive", "Joan", "Job",  "Jobs", "Jock", "Joe",  "Joel",
    "Joey", "Jog",  "John", "Join", "Joke", "Jolt", "Jot",  "Jove",
    "Joy",  "Judd", "Jude", "Judo", "Judy", "Jug",  "Juju", "Juke",
    "July", "Jump", "June", "Junk", "Juno", "Jury", "Just", "Jut",
    "Jute", "Kahn", "Kale", "Kane", "Kant", "Karl", "Kate", "Kay",
    "Keel", "Keen", "Keep", "Keg",  "Ken",  "Keno", "Kent", "Kern",
    "Kerr", "Key",  "Keys", "Kick", "Kid",  "Kill", "Kim",  "Kin",
    "Kind", "King", "Kirk", "Kiss", "Kit",  "Kite", "Klan", "Knee",
    "Knew", "Knit", "Knob", "Knot", "Know", "Koch", "Kong", "Kudo",
    "Kurd", "Kurt", "Kyle", "Lab",  "Lac",  "Lace", "Lack", "Lacy",
    "Lad",  "Lady", "Lag",  "Laid", "Lain", "Lair", "Lake", "Lam",
    "Lamb", "Lame", "Lamp", "Land", "Lane", "Lang", "Lap",  "Lard",
    "Lark", "Lass", "Last", "Late", "Laud", "Lava", "Law",  "Lawn",
    "Laws", "Lay",  "Lays", "Lazy", "Lea",  "Lead", "Leaf", "Leak",
    "Lean", "Lear", "Led",  "Lee",  "Leek", "Leer", "Left", "Leg",
    "Len",  "Lend", "Lens", "Lent", "Leo",  "Leon", "Lesk", "Less",
    "Lest", "Let",  "Lets", "Lew",  "Liar", "Lice", "Lick", "Lid",
    "Lie",  "Lied", "Lien", "Lies", "Lieu", "Life", "Lift", "Like",
    "Lila", "Lilt", "Lily", "Lima", "Limb", "Lime", "Lin",  "Lind",
    "Line", "Link", "Lint", "Lion", "Lip",  "Lisa", "List", "Lit",
    "Live", "Load", "Loaf", "Loam", "Loan", "Lob",  "Lock", "Loft",
    "Log",  "Loge", "Lois", "Lola", "Lone", "Long", "Look", "Loon",
    "Loot", "Lop",  "Lord", "Lore", "Los",  "Lose", "Loss", "Lost",
    "Lot",  "Lou",  "Loud", "Love", "Low",  "Lowe", "Loy",  "Luck",
    "Lucy", "Lug",  "Luge", "Luke", "Lulu", "Lund", "Lung", "Lura",
    "Lure", "Lurk", "Lush", "Lust", "Lye",  "Lyle", "Lynn", "Lyon",
    "Lyra", "Mac",  "Mace", "Mad",  "Made", "Mae",  "Magi", "Maid",
    "Mail", "Main", "Make", "Male", "Mali", "Mall", "Malt", "Man",
    "Mana", "Mann", "Many", "Mao",  "Map",  "Marc", "Mare", "Mark",
    "Mars", "Mart", "Mary", "Mash", "Mask", "Mass", "Mast", "Mat",
    "Mate", "Math", "Maul", "Maw",  "May",  "Mayo", "Mead", "Meal",
    "Mean", "Meat", "Meek", "Meet", "Meg",  "Mel",  "Meld", "Melt",
    "Memo", "Men",  "Mend", "Menu", "Mert", "Mesh", "Mess", "Met",
    "Mew",  "Mice", "Mid",  "Mike", "Mild", "Mile", "Milk", "Mill",
    "Milt", "Mimi", "Min",  "Mind", "Mine", "Mini", "Mink", "Mint",
    "Mire", "Miss", "Mist", "Mit",  "Mite", "Mitt", "Mix",  "Moan",
    "Moat", "Mob",  "Mock", "Mod",  "Mode", "Moe",  "Mold", "Mole",
    "Moll", "Molt", "Mona", "Monk", "Mont", "Moo",  "Mood", "Moon",
    "Moor", "Moot", "Mop",  "More", "Morn", "Mort", "Mos",  "Moss",
    "Most", "Mot",  "Moth", "Move", "Mow",  "Much", "Muck", "Mud",
    "Mudd", "Muff", "Mug",  "Mule", "Mull", "Mum",  "Murk", "Mush",
    "Must", "Mute", "Mutt", "Myra", "Myth", "Nab",  "Nag",  "Nagy",
    "Nail", "Nair", "Name", "Nan",  "Nap",  "Nary", "Nash", "Nat",
    "Nave", "Navy", "Nay",  "Neal", "Near", "Neat", "Neck", "Ned",
    "Nee",  "Need", "Neil", "Nell", "Neon", "Nero", "Ness", "Nest",
    "Net",  "New",  "News", "Newt", "Next", "Nib",  "Nibs", "Nice",
    "Nick", "Nil",  "Nile", "Nina", "Nine", "Nip",  "Nit",  "Noah",
    "Nob",  "Nod",  "Node", "Noel", "Noll", "Non",  "None", "Nook",
    "Noon", "Nor",  "Norm", "Nose", "Not",  "Note", "Noun", "Nov",
    "Nova", "Now",  "Nude", "Null", "Numb", "Nun",  "Nut",  "Oaf",
    "Oak",  "Oar",  "Oat",  "Oath", "Obey", "Oboe", "Odd",  "Ode",
    "Odin", "Off",  "Oft",  "Ohio", "Oil",  "Oily", "Oint", "Okay",
    "Olaf", "Old",  "Oldy", "Olga", "Olin", "Oman", "Omen", "Omit",
    "Once", "One",  "Ones", "Only", "Onto", "Onus", "Open", "Oral",
    "Orb",  "Ore",  "Orgy", "Orr",  "Oslo", "Otis", "Ott",  "Otto",
    "Ouch", "Our",  "Oust", "Out",  "Outs", "Ova",  "Oval", "Oven",
    "Over", "Owe",  "Owl",  "Owly", "Own",  "Owns", "Pad",  "Page",
    "Pain", "Pair", "Pal",  "Pam",  "Pan",  "Pap",  "Par",  "Park",
    "Part", "Pass", "Past", "Pat",  "Path", "Paw",  "Pay",  "Pea",
    "Peg",  "Pen",  "Pep",  "Per",  "Pet",  "Pew",  "Phi",  "Pick",
    "Pie",  "Pig",  "Pin",  "Pink", "Pit",  "Play", "Ply",  "Pod",
    "Poe",  "Pool", "Poor", "Pop",  "Pot",  "Pour", "Pow",  "Pro",
    "Pry",  "Pub",  "Pug",  "Pull", "Pun",  "Pup",  "Push", "Put",
    "Quad", "Quit", "Quo",  "Quod", "Race", "Rack", "Racy", "Raft",
    "Rag",  "Rage", "Raid", "Rail", "Rain", "Rake", "Ram",  "Ran",
    "Rank", "Rant", "Rap",  "Rare", "Rash", "Rat",  "Rate", "Rave",
    "Raw",  "Ray",  "Rays", "Read", "Real", "Ream", "Rear", "Reb",
    "Reck", "Red",  "Reed", "Reef", "Reek", "Reel", "Reid", "Rein",
    "Rena", "Rend", "Rent", "Rep",  "Rest", "Ret",  "Rib",  "Rice",
    "Rich", "Rick", "Rid",  "Ride", "Rift", "Rig",  "Rill", "Rim",
    "Rime", "Ring", "Rink", "Rio",  "Rip",  "Rise", "Risk", "Rite",
    "Road", "Roam", "Roar", "Rob",  "Robe", "Rock", "Rod",  "Rode",
    "Roe",  "Roil", "Roll", "Rome", "Ron",  "Rood", "Roof", "Rook",
    "Room", "Root", "Rosa", "Rose", "Ross", "Rosy", "Rot",  "Roth",
    "Rout", "Rove", "Row",  "Rowe", "Rows", "Roy",  "Rub",  "Rube",
    "Ruby", "Rude", "Rudy", "Rue",  "Rug",  "Ruin", "Rule", "Rum",
    "Run",  "Rung", "Runs", "Runt", "Ruse", "Rush", "Rusk", "Russ",
    "Rust", "Ruth", "Rye",  "Sac",  "Sack", "Sad",  "Safe", "Sag",
    "Sage", "Said", "Sail", "Sal",  "Sale", "Salk", "Salt", "Sam",
    "Same", "San",  "Sand", "Sane", "Sang", "Sank", "Sap",  "Sara",
    "Sat",  "Saul", "Save", "Saw",  "Say",  "Says", "Scan", "Scar",
    "Scat", "Scot", "Sea",  "Seal", "Seam", "Sear", "Seat", "Sec",
    "See",  "Seed", "Seek", "Seem", "Seen", "Sees", "Self", "Sell",
    "Sen",  "Send", "Sent", "Set",  "Sets", "Sew",  "Sewn", "Sex",
    "Shag", "Sham", "Shaw", "Shay", "She",  "Shed", "Shim", "Shin",
    "Ship", "Shod", "Shoe", "Shop", "Shot", "Show", "Shun", "Shut",
    "Shy",  "Sick", "Side", "Sift", "Sigh", "Sign", "Silk", "Sill",
    "Silo", "Silt", "Sin",  "Sine", "Sing", "Sink", "Sip",  "Sir",
    "Sire", "Sis",  "Sit",  "Site", "Sits", "Situ", "Six",  "Size",
    "Skat", "Skew", "Ski",  "Skid", "Skim", "Skin", "Skit", "Sky",
    "Slab", "Slam", "Slat", "Slay", "Sled", "Slew", "Slid", "Slim",
    "Slip", "Slit", "Slob", "Slog", "Slot", "Slow", "Slug", "Slum",
    "Slur", "Sly",  "Smog", "Smug", "Snag", "Snob", "Snow", "Snub",
    "Snug", "Soak", "Soap", "Soar", "Sob",  "Sock", "Sod",  "Soda",
    "Sofa", "Soft", "Soil", "Sold", "Some", "Son",  "Song", "Soon",
    "Soot", "Sop",  "Sore", "Sort", "Soul", "Soup", "Sour", "Sow",
    "Sown", "Soy",  "Spa",  "Spy",  "Stab", "Stag", "Stan", "Star",
    "Stay", "Stem", "Step", "Stew", "Stir", "Stop", "Stow", "Stub",
    "Stun", "Sub",  "Such", "Sud",  "Suds", "Sue",  "Suit", "Sulk",
    "Sum",  "Sums", "Sun",  "Sung", "Sunk", "Sup",  "Sure", "Surf",
    "Swab", "Swag", "Swam", "Swan", "Swat", "Sway", "Swim", "Swum",
    "Tab",  "Tack", "Tact", "Tad",  "Tag",  "Tail", "Take", "Tale",
    "Talk", "Tall", "Tan",  "Tank", "Tap",  "Tar",  "Task", "Tate",
    "Taut", "Taxi", "Tea",  "Teal", "Team", "Tear", "Tech", "Ted",
    "Tee",  "Teem", "Teen", "Teet", "Tell", "Ten",  "Tend", "Tent",
    "Term", "Tern", "Tess", "Test", "Than", "That", "The",  "Thee",
    "Them", "Then", "They", "Thin", "This", "Thud", "Thug", "Thy",
    "Tic",  "Tick", "Tide", "Tidy", "Tie",  "Tied", "Tier", "Tile",
    "Till", "Tilt", "Tim",  "Time", "Tin",  "Tina", "Tine", "Tint",
    "Tiny", "Tip",  "Tire", "Toad", "Toe",  "Tog",  "Togo", "Toil",
    "Told", "Toll", "Tom",  "Ton",  "Tone", "Tong", "Tony", "Too",
    "Took", "Tool", "Toot", "Top",  "Tore", "Torn", "Tote", "Tour",
    "Tout", "Tow",  "Town", "Toy",  "Trag", "Tram", "Tray", "Tree",
    "Trek", "Trig", "Trim", "Trio", "Trod", "Trot", "Troy", "True",
    "Try",  "Tub",  "Tuba", "Tube", "Tuck", "Tuft", "Tug",  "Tum",
    "Tun",  "Tuna", "Tune", "Tung", "Turf", "Turn", "Tusk", "Twig",
    "Twin", "Twit", "Two",  "Type", "Ugly", "Ulan", "Unit", "Urge",
    "Use",  "Used", "User", "Uses", "Utah", "Vail", "Vain", "Vale",
    "Van",  "Vary", "Vase", "Vast", "Vat",  "Veal", "Veda", "Veil",
    "Vein", "Vend", "Vent", "Verb", "Very", "Vet",  "Veto", "Vice",
    "Vie",  "View", "Vine", "Vise", "Void", "Volt", "Vote", "Wack",
    "Wad",  "Wade", "Wag",  "Wage", "Wail", "Wait", "Wake", "Wale",
    "Walk", "Wall", "Walt", "Wand", "Wane", "Wang", "Want", "War",
    "Ward", "Warm", "Warn", "Wart", "Was",  "Wash", "Wast", "Wats",
    "Watt", "Wave", "Wavy", "Way",  "Ways", "Weak", "Weal", "Wean",
    "Wear", "Web",  "Wed",  "Wee",  "Weed", "Week", "Weir", "Weld",
    "Well", "Welt", "Went", "Were", "Wert", "West", "Wet",  "Wham",
    "What", "Whee", "When", "Whet", "Who",  "Whoa", "Whom", "Why",
    "Wick", "Wide", "Wife", "Wild", "Will", "Win",  "Wind", "Wine",
    "Wing", "Wink", "Wino", "Wire", "Wise", "Wish", "Wit",  "With",
    "Wok",  "Wolf", "Won",  "Wont", "Woo",  "Wood", "Wool", "Word",
    "Wore", "Work", "Worm", "Worn", "Wove", "Wow",  "Writ", "Wry",
    "Wynn", "Yale", "Yam",  "Yang", "Yank", "Yap",  "Yard", "Yarn",
    "Yaw",  "Yawl", "Yawn", "Yea",  "Yeah", "Year", "Yell", "Yes",
    "Yet",  "Yoga", "Yoke", "You",  "Your", "Zap",  "Zero", "Zoo"
};


int
main(int argc, char *argv[]) {
    unsigned int    randd;
    char        sep = 0;
    int     	ch, i, fd;
    char        buf[sizeof(words[0])];


    while ((ch = getopt(argc, argv, "dhs")) != -1)
        switch(ch) {
        case 'd':
            sep = '-';
            break;

        case 's':
            sep = ' ';
            break;
      
        case 'h':
            fprintf(stderr, "usage: mkpasswd [-dsh]\n");
            fprintf(stderr, "  -h : print this message\n");
            fprintf(stderr, "  -d : delimit words with dashes\n");
            fprintf(stderr, "  -s : delimit words with spaces\n");
            fprintf(stderr, "  (default) : no delimiters\n");
            exit(0);
            break;
    }
          
    fd = open(RANDDEV, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "mkpasswd : unable to open " RANDDEV "\n");
        exit(errno);
    }

    for (i=0; i<WORDS_PER_PHRASE; i++) {
        read(fd, &randd, sizeof(randd));
        randd %= sizeof(words)/sizeof(words[0]);
        printf("%s", words[randd]);
        if (sep != 0 && i < WORDS_PER_PHRASE-1)
            printf("%c", sep);
    } 
    printf("\n");
}

