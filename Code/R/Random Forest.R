library(randomForest)
library(foreach)
library(doSNOW)
library(ranger)
library(plyr)
library(gbm)
library(caret)

#Parallelization
library(parallel)
library(doParallel)

all_data <- read.csv('mal_and_benign_traces.csv', header=T) #reading in the data

#Create test set for cross validation using gini scores
set.seed(134)

train_index <- sample(1:nrow(all_data), 3000, replace= FALSE)

X.train <- all_data[train_index,-c(1:6)]
Y.train <- as.factor(all_data[train_index, 1])

X.test <-  all_data[-train_index,-c(1:6)]
Y.test <-  as.factor(all_data[-train_index, 1])

summary(X.test)[2]/(summary(X.test)[1]+summary(X.test)[2])*100
summary(Y.test)[2]/(summary(Y.test)[1]+summary(Y.test)[2])*100

#First run to check variable importance
set.seed(12)
rf1 <- randomForest(X.train, Y.train, mtry = 2, ntree = 300)
var_imp <- varImpPlot(rf1, sort = TRUE, main = "Variable Importance")
  

caret_data <- all_data[train_index,-c(2:6)]
caret_test <- all_data[-train_index,-c(2:6)]

# Grid Search

#Create custom RF function for grid search in Caret 
customRF <- list(type = "Classification", library = "randomForest", loop = NULL)
customRF$parameters <- data.frame(parameter = c("mtry", "ntree"), class = rep("numeric", 2), label = c("mtry", "ntree"))
customRF$grid <- function(x, y, len = NULL, search = "grid") {}
customRF$fit <- function(x, y, wts, param, lev, last, weights, classProbs, ...) {
  randomForest(x, y, mtry = param$mtry, ntree=param$ntree, ...)
}
customRF$predict <- function(modelFit, newdata, preProc = NULL, submodels = NULL)
  predict(modelFit, newdata)
customRF$prob <- function(modelFit, newdata, preProc = NULL, submodels = NULL)
  predict(modelFit, newdata, type = "prob")
customRF$sort <- function(x) x[order(x[,1]),]
customRF$levels <- function(x) x$classes

#Start clusters
cluster <- makeCluster(detectCores()) # convention to leave 1 core for OS
registerDoParallel(cluster)

#Caret implementation of customRF
control <- trainControl(method="repeatedcv", number=10, repeats=3, search="grid", allowParallel = TRUE)
set.seed(3)
metric <- "Accuracy"
tunegrid <- expand.grid(.mtry=c(2, 6, 33), .ntree=c(100, 200, 300, 500))
rf_gridsearch <- train(as.factor(Malicious) ~., data=caret_data, method= customRF, 
                       metric=metric, tuneGrid = tunegrid, trControl=control)
print(rf_gridsearch)
plot(rf_gridsearch)


