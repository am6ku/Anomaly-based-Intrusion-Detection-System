library(randomForest)
library(foreach)
library(doSNOW)
library(ranger)
library(plyr)
library(gbm)
library(caret)

all_data <- read.csv('mal_and_benign_traces.csv', header=T) #reading in the data

#Create test set for cross validation using gini scores
set.seed(134)

train_index <- sample(1:nrow(all_data), 3000, replace= FALSE)

X.train <- all_data[train_index,-c(1:6)]
Y.train <- all_data[-train_index,-c(1:6)]

X.test = as.factor(all_data[train_index, 1])
Y.test = as.factor(all_data[-train_index, 1])

summary(Y.test)[2]/(summary(Y.test)[1]+summary(Y.test)[2])*100



#Samsize was chosen based on 1s in train data set
#Create clusters for paralellizing random forest cross vaidation for different m values and number of trees 
cluster = makeCluster(4, type = "SOCK")
registerDoSNOW(cluster)

set.seed(123)
rf1 <- foreach(mtry = c(3,6,7,49),ntree = c(100,500,1000), .combine="cbind", .multicombine=TRUE,
               .packages='randomForest') %dopar% {
                 randomForest(X.train, Y.train, mtry = mtry, ntree = ntree,
                              importance = TRUE,sampsize = c(3634,3634))
               }

#Cross validation using parallelization produced m = 3 and ntree = 1000 as optimal

#Test with Gini score 
set.seed(12)
rf_cv <- randomForest(X.train, as.factor(Y.train), mtry = 3, ntree = 1000,
                      sampsize = c(3634, 3634))
pred_cv <- predict(rf_cv, X.test, type = "prob")

preds <- pred_cv[,1]
normalized.gini.index(as.numeric(Y.test), pred_cv[,2])
#The Gini score severely over estimated our run with 100000 obs at 0.394

#Check 1s in train data
summary(as.factor(train[,1]))[2]#21694

#Running that on whole dataset
rf_final <- randomForest(train[,-c(1,2)], as.factor(train[,1]), mtry = 3, ntree = 1000,
                         sampsize = c(21694, 21694))

#Create Predicitions for submission
pred <- predict(rf_final, test, type = "prob")

prediction <- data.frame(test$id,pred[,2])
colnames(prediction) = c("id", "target")
write.csv(prediction, file = "randomforest.csv", row.names = FALSE)
