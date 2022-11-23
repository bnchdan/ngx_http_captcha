#include <gdfontl.h>
#include <gd.h>
#include <gdfontg.h>

#define CAPTCHA_HEIGHT 70

#define CAPTCHA_CHAR_ANGLE (M_PI/8)

#define CHAR_PIXEL_LENGTH 40

struct Captcha *create(int ,int ,int  , char *, char *);
void generate_captcha(struct Captcha *);
void add_chars(struct Captcha *);
void add_lines(struct Captcha *);
void destroy_captcha(struct Captcha *);
static double _norm_random_captcha();

struct Captcha{
    gdImagePtr im;
    int r, g, b;
    int char_length, number_of_lines, height, char_pixel_length;
    char *charset, *font;
    unsigned char *message;
    unsigned char *buf;
    int size;
};


static double _norm_random_captcha() {
	return rand() / (double)RAND_MAX * 2 - 1;
}

struct Captcha *create(int char_length,int number_of_lines,int  char_pixel_length, char *charset, char *font){
    struct Captcha *captcha = malloc(sizeof(struct Captcha));

    //define colors range
    captcha-> r = (int)rand()%(50)+200;
    captcha-> g = (int)rand()%(50);
    captcha-> b = (int)rand()%(50);

    captcha->char_length        = char_length;
    captcha->number_of_lines    = number_of_lines;
    captcha->height             = CAPTCHA_HEIGHT;
    captcha->char_pixel_length  = char_pixel_length;

    captcha->charset = strdup(charset);
    captcha->font    = strdup(font);

    captcha->message = malloc(sizeof(char) * captcha->char_length);

    return captcha;
}


void generate_captcha(struct Captcha *captcha){
	captcha->im = gdImageCreate(captcha->char_length * captcha->char_pixel_length, CAPTCHA_HEIGHT);   
    gdImageColorAllocate(captcha->im, 255, 255, 255);

    add_chars(captcha);
    add_lines(captcha);

}

void get_binary(struct Captcha *captcha){
    //get image to bytes
    if (!captcha->im){
        printf("nulll");
        return ;
    }
    captcha->buf= (unsigned char*)gdImagePngPtr(captcha->im, &captcha->size);
}


void add_chars(struct Captcha *captcha){
    int color_text = gdImageColorAllocate(captcha->im, captcha->r, captcha->g, captcha->b);

    int brect[8]; 
    char current_char[2] = { 0 };
    //add chars to captcha
    int i=0;
    while (1){
        current_char[0]=captcha->charset[rand() % (int)(strlen(captcha->charset) -1)];
        captcha->message[i]=(unsigned char)current_char[0];
        gdImageStringFT(    captcha->im, brect, color_text,captcha->font, 
                            30, CAPTCHA_CHAR_ANGLE * _norm_random_captcha(),
                            (captcha->char_pixel_length*i)+10, 50, current_char
                        );

        gdFreeFontCache ();
        if ( i++ == captcha->char_length - 1){       
            gdFontCacheShutdown ();
            break;colors
        }
    }
       
}

void add_lines(struct Captcha *captcha){
    int x1, y1, x2, y2;
    for (int i=0; i< captcha->number_of_lines; i++){

        x1  = (int)rand()%(captcha->char_pixel_length * captcha->char_length);
        x2  = (int)rand()%(captcha->char_pixel_length * captcha->char_length);
        y1  = (int)rand()%(captcha->height);
        y2  = (int)rand()%(captcha->height);
        
        gdImageLine(    captcha->im, 
                        x1, y1,                              
                        x2, y2,                              
                        gdImageColorAllocate(captcha->im, 0,0,0)
                    );
    }
}

void destroy_captcha(struct Captcha *captcha){
    if (captcha-> im){
        gdImageDestroy(captcha->im);
    }
    free (captcha->charset);
    free (captcha->font);
    free (captcha->buf);
    free (captcha->message);
    free (captcha);
}
