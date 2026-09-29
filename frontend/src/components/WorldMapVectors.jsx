/**
 * Accurate, high-fidelity SVG paths for World Map continents and major landmasses
 * Equirectangular projection: viewBox="0 0 1000 500"
 * lon [-180, 180] -> x [0, 1000]
 * lat [90, -90]   -> y [0, 500]
 */

export const CONTINENTS = [
  // North America & Central America
  {
    id: "north-america",
    name: "North America",
    d: `M 75 80
        L 95 65 L 125 60 L 155 62 L 180 75 L 210 65 L 245 70 L 270 55 L 305 60
        L 320 85 L 305 110 L 285 115 L 280 135 L 305 140 L 320 120 L 340 125
        L 330 150 L 315 160 L 295 180 L 285 200 L 275 220 L 270 230 L 260 230
        L 255 215 L 245 205 L 235 210 L 225 195 L 210 185 L 190 180 L 175 165
        L 160 145 L 140 130 L 120 125 L 95 115 L 75 105 Z
        M 170 125 L 185 130 L 180 140 L 170 135 Z
        M 220 220 L 235 220 L 245 235 L 235 240 L 225 230 Z`,
  },

  // Greenland
  {
    id: "greenland",
    name: "Greenland",
    d: `M 370 45
        L 420 40 L 450 55 L 430 85 L 400 95 L 375 80 L 365 60 Z`,
  },

  // South America
  {
    id: "south-america",
    name: "South America",
    d: `M 285 235
        L 310 230 L 345 240 L 385 265 L 405 285 L 390 325 L 370 365 L 350 415
        L 340 435 L 335 415 L 340 375 L 330 335 L 310 295 L 290 265 L 280 245 Z
        M 345 440 L 355 440 L 350 448 L 340 445 Z`,
  },

  // Europe (including UK, Ireland, Scandinavia, Mediterranean)
  {
    id: "europe",
    name: "Europe",
    d: `M 495 80
        L 520 65 L 545 70 L 555 90 L 540 105 L 530 100 L 525 115 L 540 125
        L 575 120 L 595 130 L 585 150 L 565 155 L 545 170 L 535 160 L 525 175
        L 510 170 L 485 175 L 475 160 L 490 145 L 485 130 L 500 120 L 495 100 Z
        M 475 105 L 490 95 L 495 115 L 485 125 L 475 115 Z
        M 465 110 L 475 105 L 470 120 L 460 115 Z
        M 525 160 L 535 155 L 540 175 L 530 180 Z`,
  },

  // Africa (including Madagascar)
  {
    id: "africa",
    name: "Africa",
    d: `M 480 185
        L 510 180 L 545 185 L 580 180 L 595 195 L 610 215 L 640 245 L 610 275
        L 590 320 L 570 365 L 550 375 L 535 345 L 530 310 L 520 280 L 485 260
        L 460 230 L 450 205 L 470 190 Z
        M 625 315 L 640 310 L 645 340 L 635 355 L 625 335 Z`,
  },

  // Asia (Middle East, Russia, India, China, SE Asia, Japan)
  {
    id: "asia",
    name: "Asia",
    d: `M 595 75
        L 640 60 L 700 65 L 770 55 L 840 60 L 890 85 L 910 110 L 890 135
        L 860 145 L 830 165 L 840 195 L 820 225 L 790 250 L 780 270 L 760 255
        L 745 220 L 715 220 L 690 195 L 660 190 L 640 195 L 615 180 L 600 150
        L 615 130 L 635 120 L 620 95 Z
        M 715 225 L 725 245 L 710 270 L 695 245 L 705 225 Z
        M 720 275 L 728 275 L 725 285 L 718 285 Z
        M 870 130 L 885 120 L 895 145 L 885 165 L 875 155 Z
        M 885 105 L 900 100 L 895 115 L 885 115 Z`,
  },

  // Southeast Asian Islands & Philippines
  {
    id: "se-islands",
    name: "Southeast Asia Islands",
    d: `M 770 280 L 795 295 L 785 305 L 765 290 Z
        M 800 305 L 825 310 L 820 320 L 795 315 Z
        M 810 265 L 830 260 L 835 285 L 820 295 L 815 275 Z
        M 850 280 L 875 285 L 885 305 L 865 305 Z`,
  },

  // Australia & New Zealand
  {
    id: "oceania",
    name: "Australia & Oceania",
    d: `M 825 330
        L 865 315 L 905 320 L 935 345 L 930 380 L 895 405 L 855 400 L 820 375
        L 815 345 Z
        M 890 415 L 905 415 L 900 425 L 888 425 Z
        M 955 405 L 970 395 L 965 415 L 950 420 Z
        M 945 425 L 960 420 L 950 445 L 940 440 Z`,
  },
];

/**
 * Standard graticule lines (latitude & longitude) for professional cartographic look
 */
export const GRATICULES = [
  // Equator
  { id: "equator", d: "M 0 250 L 1000 250", strokeDasharray: "4 4", opacity: 0.35, isPrimary: true },
  // Tropics
  { id: "tropic-cancer", d: "M 0 185 L 1000 185", strokeDasharray: "2 4", opacity: 0.2 },
  { id: "tropic-capricorn", d: "M 0 315 L 1000 315", strokeDasharray: "2 4", opacity: 0.2 },
  // Prime Meridian & major meridians
  { id: "meridian-0", d: "M 500 0 L 500 500", strokeDasharray: "4 4", opacity: 0.35, isPrimary: true },
  { id: "meridian-w120", d: "M 167 0 L 167 500", strokeDasharray: "2 4", opacity: 0.2 },
  { id: "meridian-w60", d: "M 333 0 L 333 500", strokeDasharray: "2 4", opacity: 0.2 },
  { id: "meridian-e60", d: "M 667 0 L 667 500", strokeDasharray: "2 4", opacity: 0.2 },
  { id: "meridian-e120", d: "M 833 0 L 833 500", strokeDasharray: "2 4", opacity: 0.2 },
];
