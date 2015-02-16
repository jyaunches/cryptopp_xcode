//
//  ViewController.m
//  CryptoPPTest
//
//  Created by Julietta Yaunches on 2/5/15.
//  Copyright (c) 2015 Julietta Yaunches. All rights reserved.
//

#import "ViewController.h"
#import "EncryptionService.h"


@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    EncryptionService *service = [[EncryptionService alloc] init];
    [service doStuff];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
